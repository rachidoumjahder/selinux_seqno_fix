// SPDX-License-Identifier: GPL-2.0
/*
 * Repair the SELinux status page after KernelSU publishes policyload=0.
 *
 * The module resolves only selinux_kernel_status_page(), performs one
 * conditional repair, and leaves the access-decision path untouched.
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
static unsigned long status_fixups;

typedef struct page *(*selinux_kernel_status_page_fn)(void);

static void *resolve_symbol_with_kprobe(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name,
	};
	void *address;
	int ret;

	ret = register_kprobe(&kp);
	if (ret)
		return NULL;

	address = (void *)kp.addr;
	unregister_kprobe(&kp);
	return address;
}

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

static int __init selinux_seqno_fix_init(void)
{
	selinux_kernel_status_page_fn status_page_fn;
	struct selinux_kernel_status_compat *status;
	struct page *page;

	status_page_fn = (selinux_kernel_status_page_fn)
		resolve_symbol_with_kprobe("selinux_kernel_status_page");
	if (!status_page_fn) {
		pr_err("failed to resolve selinux_kernel_status_page\n");
		return -ENOENT;
	}

	page = status_page_fn();
	if (!page) {
		pr_err("SELinux status page is unavailable\n");
		return -ENOMEM;
	}

	status = page_address(page);
	if (!status) {
		pr_err("SELinux status page has no direct mapping\n");
		return -EFAULT;
	}

	publish_policyload_one(status);
	pr_info("loaded; status sequence=%u policyload=%u fixups=%lu\n",
		READ_ONCE(status->sequence), READ_ONCE(status->policyload),
		status_fixups);
	return 0;
}

static void __exit selinux_seqno_fix_exit(void)
{
	pr_info("unloaded (fixups=%lu)\n", status_fixups);
}

module_init(selinux_seqno_fix_init);
module_exit(selinux_seqno_fix_exit);

MODULE_AUTHOR("Andrea-Lyz, Codex");
MODULE_DESCRIPTION("One-shot repair for KSU's zeroed SELinux status.policyload");
MODULE_LICENSE("GPL");
