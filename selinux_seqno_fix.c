// SPDX-License-Identifier: GPL-2.0
/*
 * Repair the SELinux status page after KernelSU publishes policyload=0.
 *
 * A return probe on selinux_kernel_status_page() repairs the page immediately
 * after SELinux returns it. The module never invokes that non-exported
 * function directly and leaves the access-decision path untouched.
 *
 * The repair is deliberately gated: policyload must be zero and the status
 * page must already describe a loaded policy. Every non-zero value is left
 * untouched, including genuine policy reload notifications.
 */

#define pr_fmt(fmt) "selinux_seqno_fix: " fmt

#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>

struct selinux_kernel_status_compat {
	u32 version;
	u32 sequence;
	u32 enforcing;
	u32 policyload;
	u32 deny_unknown;
};

static DEFINE_SPINLOCK(status_repair_lock);
static unsigned long status_page_hits;
static unsigned long status_fixups;
static unsigned long version_reads;
static unsigned long version_sanitizations;
static bool version_probe_registered;

struct version_probe_data {
	struct seq_file *seq;
	size_t start_count;
};

static void publish_policyload_one(struct selinux_kernel_status_compat *status)
{
	unsigned long flags;
	u32 sequence;
	u32 policyload;

	spin_lock_irqsave(&status_repair_lock, flags);
	sequence = READ_ONCE(status->sequence);
	policyload = READ_ONCE(status->policyload);

	/*
	 * version==1 is the ABI used by libselinux. A positive sequence means
	 * the policy status page has completed at least one publication.
	 */
	if (READ_ONCE(status->version) != 1 || !sequence || policyload != 0) {
		spin_unlock_irqrestore(&status_repair_lock, flags);
		return;
	}

	if (sequence & 1U)
		sequence++;

	WRITE_ONCE(status->sequence, sequence + 1);
	smp_wmb();
	WRITE_ONCE(status->policyload, 1);
	smp_wmb();
	WRITE_ONCE(status->sequence, sequence + 2);
	status_fixups++;
	spin_unlock_irqrestore(&status_repair_lock, flags);

	pr_info("repaired status.policyload 0 -> 1 (sequence %u -> %u, fixups=%lu)\n",
		sequence, sequence + 2, status_fixups);
}

static int status_page_return_handler(struct kretprobe_instance *ri,
				      struct pt_regs *regs)
{
	struct selinux_kernel_status_compat *status;
	struct page *page;

	page = (struct page *)regs_return_value(regs);
	if (!page)
		return 0;

	status = page_address(page);
	if (!status)
		return 0;

	status_page_hits++;
	publish_policyload_one(status);
	return 0;
}

static struct kretprobe status_page_kretprobe = {
	.handler = status_page_return_handler,
	.maxactive = 16,
	.kp = {
		.symbol_name = "selinux_kernel_status_page",
	},
};

/*
 * MuMu's otherwise stock-looking linux_proc_banner contains
 * "build-user@build-host".  Duck Detector treats any @mention in
 * /proc/version as a custom-kernel signal.  Capture the seq_file at entry,
 * then replace only @ bytes appended by version_proc_show().  The replacement
 * is length-preserving, so seq_file accounting and userspace read offsets are
 * unchanged.
 */
static int version_proc_entry_handler(struct kretprobe_instance *ri,
				      struct pt_regs *regs)
{
	struct version_probe_data *data = ri->data;
	struct seq_file *seq;

	seq = (struct seq_file *)regs_get_kernel_argument(regs, 0);
	data->seq = seq;
	data->start_count = seq ? READ_ONCE(seq->count) : 0;
	return 0;
}

static int version_proc_return_handler(struct kretprobe_instance *ri,
				       struct pt_regs *regs)
{
	struct version_probe_data *data = ri->data;
	struct seq_file *seq = data->seq;
	size_t count;
	size_t i;
	unsigned int replacements = 0;

	if ((long)regs_return_value(regs) != 0 || !seq || !READ_ONCE(seq->buf))
		return 0;

	count = READ_ONCE(seq->count);
	if (data->start_count >= count || count > READ_ONCE(seq->size))
		return 0;

	version_reads++;
	for (i = data->start_count; i < count; i++) {
		if (READ_ONCE(seq->buf[i]) == '@') {
			WRITE_ONCE(seq->buf[i], '-');
			replacements++;
		}
	}

	if (replacements) {
		version_sanitizations += replacements;
		pr_info("sanitized %u @ byte(s) from /proc/version (total=%lu)\n",
			replacements, version_sanitizations);
	}

	return 0;
}

static struct kretprobe version_proc_kretprobe = {
	.entry_handler = version_proc_entry_handler,
	.handler = version_proc_return_handler,
	.data_size = sizeof(struct version_probe_data),
	.maxactive = 16,
	.kp = {
		.symbol_name = "version_proc_show",
	},
};

static int __init selinux_seqno_fix_init(void)
{
	int ret;

	ret = register_kretprobe(&status_page_kretprobe);
	if (ret) {
		pr_err("failed to register selinux_kernel_status_page kretprobe: %d\n",
		       ret);
		return ret;
	}

	ret = register_kretprobe(&version_proc_kretprobe);
	if (ret) {
		pr_warn("version_proc_show probe unavailable: %d; SELinux repair remains active\n",
			ret);
	} else {
		version_probe_registered = true;
		pr_info("/proc/version sanitizer active\n");
	}

	pr_info("loaded; waiting for SELinux status-page access\n");
	return 0;
}

static void __exit selinux_seqno_fix_exit(void)
{
	if (version_probe_registered)
		unregister_kretprobe(&version_proc_kretprobe);
	unregister_kretprobe(&status_page_kretprobe);
	pr_info("unloaded (page_hits=%lu fixups=%lu version_reads=%lu sanitized=%lu)\n",
		status_page_hits, status_fixups, version_reads,
		version_sanitizations);
}

module_init(selinux_seqno_fix_init);
module_exit(selinux_seqno_fix_exit);

MODULE_AUTHOR("Andrea-Lyz, Codex");
MODULE_DESCRIPTION("Repair KSU SELinux status and sanitize MuMu /proc/version identity");
MODULE_LICENSE("GPL");
