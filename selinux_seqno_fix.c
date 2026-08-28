// SPDX-License-Identifier: GPL-2.0
/*
 * Repair the SELinux status page after KernelSU publishes policyload=0.
 *
 * Duck Detector obtains this page through selinux_kernel_status_page(). A
 * kretprobe on that narrow accessor lets us repair the page immediately
 * before userspace maps it. This avoids calling non-exported SELinux
 * functions from module init and avoids probing the access-decision path.
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
#include <linux/spinlock.h>
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

static int __init selinux_seqno_fix_init(void)
{
	int ret;

	ret = register_kretprobe(&status_page_kretprobe);
	if (ret) {
		pr_err("failed to register selinux_kernel_status_page kretprobe: %d\n",
		       ret);
		return ret;
	}

	pr_info("loaded; waiting for SELinux status-page access\n");
	return 0;
}

static void __exit selinux_seqno_fix_exit(void)
{
	unregister_kretprobe(&status_page_kretprobe);
	pr_info("unloaded (page_hits=%lu fixups=%lu)\n",
		status_page_hits, status_fixups);
}

module_init(selinux_seqno_fix_init);
module_exit(selinux_seqno_fix_exit);

MODULE_AUTHOR("Andrea-Lyz, Codex");
MODULE_DESCRIPTION("Repair KSU's zeroed SELinux status.policyload on status-page access");
MODULE_LICENSE("GPL");
