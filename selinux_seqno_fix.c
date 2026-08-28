// SPDX-License-Identifier: GPL-2.0
/*
 * Repair the SELinux status page after KernelSU's policy-hiding hook stomps
 * `status.policyload` to 0 via apply_kernelsu_rules() ->
 * selinux_status_update_policyload(0). The repair publishes the live AVC
 * seqno through the same seqlock writer protocol the kernel itself uses, so
 * userspace seqlock readers never observe a torn intermediate state.
 *
 * Strictly bounded behavior:
 *   - We only intervene when status.policyload was just set to 0 *and* the
 *     AVC has a positive policy seqno to restore from. Any non-zero
 *     status.policyload — including a freshly bumped value from a real
 *     sel_write_load() / security_load_policy() hot reload — is left
 *     completely alone, so libselinux and servicemanager continue to
 *     observe the kernel's own monotonic policyload increments and refresh
 *     their AVC caches accordingly.
 *   - status.sequence is always advanced monotonically (even -> odd ->
 *     even+2) by our seqlock writer; we never roll it back or block the
 *     kernel's own increments.
 *
 * The repair never touches allowed/auditallow/auditdeny/flags and never
 * influences access decisions; it only restores metadata that KSU's own
 * code zeroes for what is really only a userspace-cache-flush side
 * channel.
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

struct av_decision_compat {
	u32 allowed;
	u32 auditallow;
	u32 auditdeny;
	u32 seqno;
	u32 flags;
};

struct selinux_kernel_status_compat {
	u32 version;
	u32 sequence;
	u32 enforcing;
	u32 policyload;
	u32 deny_unknown;
};

typedef struct page *(*selinux_kernel_status_page_fn)(void);
typedef u32 (*avc_policy_seqno_fn)(void);

struct seqno_fix_data {
	struct av_decision_compat *avd;
};

static struct selinux_kernel_status_compat *status_page_addr;
static avc_policy_seqno_fn avc_policy_seqno_ptr;
static DEFINE_SPINLOCK(status_repair_lock);

static bool enabled = true;
static unsigned long av_user_hits;
static unsigned long policyload_hook_hits;
static unsigned long status_fixups;
static unsigned long status_passthrough;
static unsigned long av_user_no_status;
static unsigned long av_user_null_avd;
static unsigned int last_status_sequence;
static unsigned int last_status_policyload;
static unsigned int last_avc_policy_seqno;
static unsigned int last_avd_seqno;
static unsigned int last_repair_target;

/*
 * Keep diagnostics internal on MuMu. Exporting them as module parameters
 * imports param_ops_* symbols whose CRCs differ from the public GKI build,
 * even though the kprobe and SELinux interfaces used by the repair match.
 */

static void bump_counter(unsigned long *counter)
{
	WRITE_ONCE(*counter, READ_ONCE(*counter) + 1);
}

static u32 read_avc_policy_seqno(void)
{
	avc_policy_seqno_fn fn = READ_ONCE(avc_policy_seqno_ptr);
	u32 seqno;

	if (!fn)
		return 0;

	seqno = fn();
	if (seqno)
		WRITE_ONCE(last_avc_policy_seqno, seqno);
	return seqno;
}

static void *resolve_symbol_with_kprobe(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name,
	};
	void *addr;
	int ret;

	ret = register_kprobe(&kp);
	if (ret)
		return NULL;

	addr = (void *)kp.addr;
	unregister_kprobe(&kp);
	return addr;
}

static bool status_page_ready(struct selinux_kernel_status_compat **out)
{
	struct selinux_kernel_status_compat *status;

	status = READ_ONCE(status_page_addr);
	if (!status || !READ_ONCE(status->version))
		return false;

	*out = status;
	return true;
}

/*
 * Mirror selinux_status_update_status()'s seqlock writer side: bump sequence
 * to an odd value, publish the new policyload, then bump sequence back to an
 * even value, with smp_wmb() between writes. This is monotonic; we never
 * roll the sequence number back, so userspace readers that latch on
 * sequence advance always see at least the same number of "things changed"
 * notifications as without this module loaded.
 */
static void seqlock_publish_policyload(struct selinux_kernel_status_compat *status,
				       u32 target)
{
	u32 sequence = READ_ONCE(status->sequence);

	/* Make sure we start from an even baseline. */
	if (sequence & 1U)
		sequence++;

	WRITE_ONCE(status->sequence, sequence + 1);
	smp_wmb();
	WRITE_ONCE(status->policyload, target);
	smp_wmb();
	WRITE_ONCE(status->sequence, sequence + 2);
}

/*
 * Strictly bounded repair entry point. Returns true when the status page was
 * examined (whether or not we wrote it), false when we could not even
 * inspect it (no target, or status page not yet mapped).
 *
 * The gate inside the lock is the project's whole semantic claim:
 *
 *   "Only repair the KSU stomp-to-zero pattern. Leave every other state of
 *    status.policyload — including post-boot baselines, setbool-induced
 *    AVC seqno advances, and real hot policy reloads — completely
 *    untouched."
 *
 * This keeps libselinux and servicemanager's policy-change observation
 * channel intact: a real hot reload writes a positive policyload and we
 * never overwrite it; a setbool advances avc_policy_seqno without bumping
 * status.policyload (which is normal AOSP behavior, even though some
 * detectors wrongly assume the two must match) and we leave that alone too.
 */
static bool repair_status_policyload(u32 target)
{
	struct selinux_kernel_status_compat *status;
	unsigned long flags;
	u32 sequence_before;
	u32 policyload_before;

	if (!target)
		return false;

	if (!status_page_ready(&status))
		return false;

	spin_lock_irqsave(&status_repair_lock, flags);

	sequence_before = READ_ONCE(status->sequence);
	policyload_before = READ_ONCE(status->policyload);
	WRITE_ONCE(last_status_sequence, sequence_before);
	WRITE_ONCE(last_status_policyload, policyload_before);

	if (policyload_before != 0) {
		/*
		 * Either the page is already at a positive baseline (e.g.
		 * 6.12+ early boot 4/1, or any post-boot 6.6 state after a
		 * real load_policy), or a real hot reload just wrote a new
		 * positive policyload that userspace must observe. Hands off.
		 */
		bump_counter(&status_passthrough);
		spin_unlock_irqrestore(&status_repair_lock, flags);
		return true;
	}

	/*
	 * policyload_before == 0 here. On pre-6.12 kernels this is also the
	 * legitimate very-early-boot state, but in that case avc_policy_seqno
	 * is also 0 and the !target check above already returned false; so by
	 * the time we reach this point we have target > 0, meaning the AVC
	 * has at least one policy generation, meaning the only way for
	 * status.policyload to still be 0 is the KSU stomp.
	 */
	seqlock_publish_policyload(status, target);
	WRITE_ONCE(last_repair_target, target);
	bump_counter(&status_fixups);

	spin_unlock_irqrestore(&status_repair_lock, flags);

	pr_debug("repaired KSU policyload stomp 0 -> %u (seq %u)\n",
		 target, sequence_before);
	return true;
}

/*
 * security_compute_av_user kretprobe: a continuous safety net. If the
 * primary kretprobe on selinux_status_update_policyload could not be
 * registered (e.g. the symbol got inlined or LTO'd out on this build), or
 * if KSU stomped before the module was loaded, this path catches the
 * stomp lazily on the next userspace /access query.
 */
static int seqno_fix_entry_handler(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct seqno_fix_data *data = (struct seqno_fix_data *)ri->data;

#if defined(CONFIG_ARM64)
	/* security_compute_av_user(..., avd) passes avd as the fourth argument. */
	data->avd = (struct av_decision_compat *)regs->regs[3];
#elif defined(CONFIG_X86_64)
	/* x86_64: 4th argument is in rcx */
	data->avd = (struct av_decision_compat *)regs->cx;
#else
	data->avd = NULL;
#endif

	return 0;
}

static int seqno_fix_return_handler(struct kretprobe_instance *ri,
				    struct pt_regs *regs)
{
	struct seqno_fix_data *data = (struct seqno_fix_data *)ri->data;
	struct av_decision_compat *avd = data->avd;
	u32 avd_seqno;
	u32 avc_seqno;
	u32 target;

	if (!READ_ONCE(enabled))
		return 0;

	bump_counter(&av_user_hits);

	if (!avd) {
		bump_counter(&av_user_null_avd);
		return 0;
	}

	avd_seqno = READ_ONCE(avd->seqno);
	if (avd_seqno)
		WRITE_ONCE(last_avd_seqno, avd_seqno);

	avc_seqno = read_avc_policy_seqno();
	target = avc_seqno ? avc_seqno : avd_seqno;

	if (!repair_status_policyload(target))
		bump_counter(&av_user_no_status);
	return 0;
}

static struct kretprobe compute_av_user_kretprobe = {
	.handler = seqno_fix_return_handler,
	.entry_handler = seqno_fix_entry_handler,
	.data_size = sizeof(struct seqno_fix_data),
	.maxactive = 64,
	.kp = {
		.symbol_name = "security_compute_av_user",
	},
};

/*
 * selinux_status_update_policyload kretprobe: the primary trigger. Fires
 * after every status-page policyload update. Real hot reloads write a
 * positive policyload and the gate inside repair_status_policyload skips
 * them; only KSU's update_policyload(0) reaches the writer path.
 */
static int policyload_update_return_handler(struct kretprobe_instance *ri,
					    struct pt_regs *regs)
{
	u32 avc_seqno;

	if (!READ_ONCE(enabled))
		return 0;

	bump_counter(&policyload_hook_hits);

	avc_seqno = read_avc_policy_seqno();
	repair_status_policyload(avc_seqno);
	return 0;
}

static struct kretprobe policyload_update_kretprobe = {
	.handler = policyload_update_return_handler,
	.maxactive = 16,
	.kp = {
		.symbol_name = "selinux_status_update_policyload",
	},
};

static int __init selinux_seqno_fix_init(void)
{
	selinux_kernel_status_page_fn status_page_fn;
	struct page *status_page;
	u32 seed_seqno;
	int ret;

#if !defined(CONFIG_ARM64) && !defined(CONFIG_X86_64)
	pr_err("unsupported architecture; this module expects arm64 or x86_64\n");
	return -EOPNOTSUPP;
#endif

	status_page_fn = (selinux_kernel_status_page_fn)
		resolve_symbol_with_kprobe("selinux_kernel_status_page");
	if (!status_page_fn) {
		pr_err("failed to resolve selinux_kernel_status_page\n");
		return -ENOENT;
	}

	avc_policy_seqno_ptr = (avc_policy_seqno_fn)
		resolve_symbol_with_kprobe("avc_policy_seqno");
	if (!avc_policy_seqno_ptr)
		pr_warn("failed to resolve avc_policy_seqno; status repair will use observed avd seqno only\n");

	status_page = status_page_fn();
	if (!status_page) {
		pr_err("SELinux status page is unavailable\n");
		return -ENOMEM;
	}

	status_page_addr = page_address(status_page);
	if (!status_page_addr) {
		pr_err("SELinux status page has no direct mapping\n");
		return -EFAULT;
	}

	/*
	 * Seed pass: only repairs if the page is currently in stomp state
	 * (policyload == 0 with a positive avc_seqno). Pre-6.12 early-boot
	 * state 0/0 has avc_seqno == 0 and is left alone; 6.12+ baseline
	 * 4/1 has policyload != 0 and is also left alone.
	 */
	seed_seqno = read_avc_policy_seqno();
	repair_status_policyload(seed_seqno);

	ret = register_kretprobe(&policyload_update_kretprobe);
	if (ret) {
		pr_warn("failed to register selinux_status_update_policyload kretprobe: %d (continuing with /access path only)\n",
			ret);
		policyload_update_kretprobe.kp.addr = NULL;
	}

	ret = register_kretprobe(&compute_av_user_kretprobe);
	if (ret) {
		pr_err("failed to register security_compute_av_user kretprobe: %d\n", ret);
		if (policyload_update_kretprobe.kp.addr)
			unregister_kretprobe(&policyload_update_kretprobe);
		return ret;
	}

	pr_info("loaded; seed avc_seqno=%u status.policyload=%u (fixups=%lu passthrough=%lu)\n",
		seed_seqno, READ_ONCE(last_status_policyload),
		READ_ONCE(status_fixups), READ_ONCE(status_passthrough));
	return 0;
}

static void __exit selinux_seqno_fix_exit(void)
{
	unregister_kretprobe(&compute_av_user_kretprobe);
	if (policyload_update_kretprobe.kp.addr)
		unregister_kretprobe(&policyload_update_kretprobe);
	pr_info("unloaded\n");
}

module_init(selinux_seqno_fix_init);
module_exit(selinux_seqno_fix_exit);

MODULE_AUTHOR("Andrea-Lyz, Codex");
MODULE_DESCRIPTION("Restore SELinux status.policyload after KSU stomps it on policy load (stomp-only gate, real hot reloads pass through)");
MODULE_LICENSE("GPL");
