# selinux_seqno_fix

> **Status: temporary stop-gap.** This module exists only because current
> KernelSU builds expose a `status.policyload == 0` vs `access.avd.seqno > 0`
> split through `apply_kernelsu_rules() -> selinux_status_update_policyload(0)`.
> Once that bug is fixed upstream — most likely by simply dropping the
> `selinux_status_update_policyload(0)` call in `kernel/selinux/rules.c`, since
> KSU's hidden rules patch `avd.allowed` directly and don't actually need to
> invalidate userspace SELinux status caches — this module becomes a historical
> artifact and should be unloaded. Track KernelSU upstream and stop using this
> the day a release lands that no longer produces the split.
>
> **Detector-oriented engineering.** This project is written against the
> detection surface — specifically the
> [Duck Detector](https://github.com/eltavine/Duck-Detector-Refactoring)
> policyload/avd.seqno oracle and the
> [ksu-edge-seqno-demo](https://github.com/AAndreaLyz/ksu-edge-seqno-demo)
> PoC. It does not add any new capabilities to KernelSU, does not weaken
> SELinux enforcement, and does not alter access decisions. It only restores
> metadata that KSU's own code incorrectly zeroes, making the kernel's
> observable state consistent with what AOSP would produce without KSU
> installed. If you're looking for a "cheat" — this isn't one; it's a
> correctness patch for a metadata side-channel leak.
>
> **The detector premise is itself questionable.** AOSP does not actually
> guarantee `status.policyload == access.avd.seqno`; the two counters track
> different things (policy reload generation vs. AVC cache generation) and
> diverge naturally on any device that has ever changed an SELinux boolean.
> Detectors that treat equality as a coherence contract are extrapolating
> from an empirical observation, not a kernel API. We mirror their
> assumption only because it is the one shipping in the wild.

Tiny Android kernel module for the SELinux `/sys/fs/selinux/status` and
`/sys/fs/selinux/access` seqno split exposed by KernelSU policy hiding.

The module restores `status.policyload` to the live AVC `seqno` whenever
something (typically KernelSU's `apply_kernelsu_rules() ->
selinux_status_update_policyload(0)`) zeroes it. The repair is performed
through the same seqlock dance used by the kernel's own writer, so userspace
readers never observe a torn intermediate state. It does not change `allowed`,
`auditallow`, `auditdeny`, or `flags` and never affects access decisions.

## Detection model

The Duck Detector / `ksu-edge-seqno-demo` clean baseline is:

```text
status.sequence is even and stable
status.policyload > 0
access.avd.seqno > 0
status.policyload == access.avd.seqno
```

Detectors flag a split when `status.policyload == 0` (or otherwise diverges
from `access.avd.seqno`) while `status.sequence` is nonzero. Pulling
`access.avd.seqno` to zero would be visible too, so this module instead
restores `status.policyload` to the live `avc_policy_seqno()` value, matching
the AOSP coherence contract.

## How it works

1. At load, the module resolves `selinux_kernel_status_page()` and
   `avc_policy_seqno()` with one-shot kprobes, maps the status page, and runs
   one **conditional** seed pass (see "Bounded repair" below).
2. A kretprobe on `selinux_status_update_policyload` is the primary trigger.
   It only republishes the AVC seqno when `status.policyload == 0` is
   observed; any non-zero value (including a freshly bumped value from a
   real `sel_write_load() -> security_load_policy()` hot reload) passes
   straight through to userspace. This keeps libselinux and `servicemanager`
   able to detect real policy reloads through their normal status-page
   channel.
3. A kretprobe on `security_compute_av_user` acts as a safety net for the
   case where the policyload symbol cannot be probed or where the stomp
   happened before the module was loaded.
4. When the module does write, it uses the same seqlock writer protocol
   (`sequence` even -> odd -> even+2 with `smp_wmb()` between writes) that
   `selinux_status_update_status()` uses, so userspace seqlock-stable
   readers never observe a torn page. `status.sequence` is only ever
   advanced; we never roll it back.

## Bounded repair

The repair is gated to one specific pattern: **`status.policyload` was just
set to 0 and the AVC has a positive seqno**. Anything else is left
untouched. Concretely:

| State observed                                                | Action               |
|---------------------------------------------------------------|----------------------|
| `policyload == 0`, `avc_seqno > 0` (KSU stomp)                | Repair               |
| `policyload > 0` (real hot reload, or already-coherent state) | Pass through         |
| `policyload == 0`, `avc_seqno == 0` (pre-6.12 boot early)     | Pass through         |
| 6.12+ early boot baseline `sequence=4, policyload=1`          | Pass through         |

This is the second-iteration design after maintainer feedback. The earlier
"unconditionally align policyload to avc_seqno" approach would have
suppressed the userspace-visible signal of a real policy hot reload,
breaking `servicemanager`'s policy-change detection and any other consumer
of `selinux_status_open() / selinux_status_updated()`. The current gate
preserves every legitimate userspace cache-flush signal and only filters
out the artificial KSU stomp.

## Build target

The bundled GitHub Actions workflow builds for the maintainer's own
device against the OnePlus 13 SM8750 6.6.89 kernel:

- kernel repo: `cctv18/android_kernel_common_oneplus_sm8750`
- kernel branch: `oneplus/sm8750_v_16.0.0_oneplus_13_6.6.89`
- toolchain: `LLVM-Clang18-r510928`
- default localversion suffix:
  `android15-8-g7e1f3c083cc6-abogki467167594-4k`

For other kernels you must build the module yourself against the matching
kernel tree. The C source itself is portable to any arm64 Android kernel
that exports (or has resolvable via kallsyms) `selinux_kernel_status_page`,
`selinux_status_update_policyload`, `avc_policy_seqno`, and
`security_compute_av_user`. Pull the source, point `KDIR` at your kernel,
and build:

```sh
make KDIR=/path/to/kernel/source O=/path/to/kernel/out ARCH=arm64 LLVM=1
```

The module's `obj-m` declaration lives in `Kbuild`, with `Makefile` only
providing the wrapper targets. Do not collapse them back into a single
`Makefile` with a `KERNELRELEASE` guard: in some Android 6.6 kbuild trees
the guard form silently produces an empty `obj-m` for the external pass
and modpost finishes without compiling anything.

Output:

```text
selinux_seqno_fix.ko
```

## GitHub Actions

Run **Build selinux_seqno_fix.ko** from the Actions tab. The artifact
contains the raw `.ko` and a flashable KSU/Magisk-style zip that loads it
from `service.sh`.

The workflow tries the fast path first: `gki_defconfig`,
`modules_prepare`, and then the external module build. If
`out/Module.symvers` is missing, it automatically builds in-tree `modules`
once to generate the kernel symbol versions required by modpost. Enable
`full_kernel_build` only when you want to force that slow path from the
start.

CI uses GitHub cache for downloaded archives, the unpacked
kernel/toolchain, and `kernel_workspace/out`. The first run for a kernel
branch/suffix is still slow because it has to populate `Module.symvers`;
later module-only changes should reuse the cached `out/` tree and finish
much faster.

The CI artifact is built for one specific kernel release. If `uname -r`
on your phone differs, build locally or rerun the workflow with a matching
`kernel_suffix` and kernel branch.

## Load

```sh
su -c 'insmod /data/local/tmp/selinux_seqno_fix.ko'
su -c 'dmesg | grep selinux_seqno_fix'
```

After loading, confirm the module and kretprobes initialized:

```sh
su -c 'grep selinux_seqno_fix /proc/modules'
su -c 'dmesg | grep selinux_seqno_fix'
```

The MuMu-compatible build keeps counters internal instead of exporting
module parameters. MuMu's kernel gives the public GKI `param_ops_*`
symbols different modversion CRCs, while the interfaces used by the
repair itself remain compatible.

Unload:

```sh
su -c 'rmmod selinux_seqno_fix'
```

## Notes

- Requires `CONFIG_KPROBES` and `CONFIG_KRETPROBES`.
- Resolves `selinux_kernel_status_page()`,
  `selinux_status_update_policyload()` and `avc_policy_seqno()` via
  temporary kprobes at load time.
- Supports arm64 and x86_64 Android kernels.
- If the primary `selinux_status_update_policyload` kretprobe cannot be
  registered, the module continues with the `security_compute_av_user`-only
  safety-net path. If `selinux_kernel_status_page()` cannot be resolved at
  all, the module refuses to load rather than guessing structure offsets.

## Lifetime / when to retire this module

This module is a workaround for a single, well-localized KernelSU side
effect. It is expected to be obsoleted upstream. The cleanest fix is in
KernelSU itself: drop `selinux_status_update_policyload(0)` from
`apply_kernelsu_rules()` in `kernel/selinux/rules.c`. KSU's hook rules
patch `avd.allowed` directly, so nothing needs to invalidate the
userspace SELinux status page; the call is collateral damage left over
from an earlier design.

When that lands upstream:

1. The split goes away on its own — `status.policyload` no longer gets
   stomped.
2. The Duck Detector / `ksu-edge-seqno-demo` policyload/avd.seqno oracle
   returns to `clean` without any kernel module.
3. This repo should be archived. Keep the tag/release as a historical
   record of the side effect and stop using `insmod selinux_seqno_fix.ko`.

Until then, treat this module as a short-lived patch, not a long-term
component. No new detectors or features should be built around it.
