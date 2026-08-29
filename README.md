# selinux_seqno_fix

The module now contains narrowly scoped return probes for the MuMu
6.1.90-perf+ research image:

- repair a zeroed SELinux status-page `policyload` value after KernelSU;
- replace `@` with `-` only in output appended by `version_proc_show()`,
  removing the `build-user@build-host` false positive from `/proc/version`.
- present length-preserving neutral aliases for MuMu's exact `/vendor` source
  and `/data/local/tmp/fake_*` target strings in `/proc/mounts` and
  `/proc/mountinfo` output.
- present a neutral name for the otherwise-unused overlayfs capability in
  `/proc/filesystems`, without unregistering the driver or changing mounts.
- alias the exact `zz_mumu_libdl_overlay_test` mountinfo root used by the
  audited dlclose-prologue overlay, without changing its target or backing.

The version sanitizer is optional at runtime: if its kernel symbol cannot be
probed, the SELinux repair still loads and operates normally.

The mount sanitizers are optional and exact-pattern scoped. They change only
emitted text from `show_vfsmnt()`, `show_mountinfo()`, and
`filesystems_proc_show()`; they do not alter mounts, namespaces, devices, or
registered filesystem drivers. Avoiding task and module-parameter lookups also
keeps the module within the small verified symbol surface exposed by the target
MuMu kernel.

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

On the MuMu target, the module restores a zeroed `status.policyload` to the
normal positive boot-policy baseline immediately before userspace maps the
status page. The repair uses the same seqlock dance as the kernel writer, so
readers never observe a torn intermediate state. It does not change
`allowed`, `auditallow`, `auditdeny`, or `flags` and never affects access
decisions.

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
restores `status.policyload` to the target's observed baseline value of 1.

## How it works

1. Module init registers one kretprobe on
   `selinux_kernel_status_page()` and never calls that function directly.
2. Its return handler checks the returned page ABI, sequence, and policyload.
3. Only the MuMu stomp state (`version == 1`, positive sequence,
   `policyload == 0`) is repaired. Every positive policyload passes through.
4. The write uses the same seqlock writer protocol
   (`sequence` even -> odd -> even+2 with `smp_wmb()` between writes) that
   `selinux_status_update_status()` uses, so userspace seqlock-stable
   readers never observe a torn page. `status.sequence` is only ever
   advanced; we never roll it back.

## Bounded repair

The repair is gated to one specific pattern: **the status ABI is initialized,
its sequence is positive, and `status.policyload` is 0**. Anything else is
left untouched. Concretely:

| State observed                                                | Action               |
|---------------------------------------------------------------|----------------------|
| `policyload == 0`, positive status sequence (KSU stomp)       | Repair to 1          |
| `policyload > 0` (real hot reload, or already-coherent state) | Pass through         |
| `policyload == 0`, status sequence 0 (early boot)             | Pass through         |
| 6.12+ early boot baseline `sequence=4, policyload=1`          | Pass through         |

This is the second-iteration design after maintainer feedback. The earlier
"unconditionally align policyload to avc_seqno" approach would have
suppressed the userspace-visible signal of a real policy hot reload,
breaking `servicemanager`'s policy-change detection and any other consumer
of `selinux_status_open() / selinux_status_updated()`. The current gate
preserves every legitimate userspace cache-flush signal and only filters
out the artificial KSU stomp.

## Build target

The bundled GitHub Actions workflow builds for MuMu Player 12's x86_64
Android 15 kernel:

- kernel repo: `ramabondanp/android_kernel_common-6.1`
- kernel branch: `android14-6.1`
- toolchain: `LLVM-Clang18-r510928`
- release: `6.1.90-perf+`
- target `module_layout` CRC: `0xc4965eab`

For other kernels you must build the module yourself against the matching
kernel tree. The C source itself is portable to arm64 and x86_64 Android
kernels where `selinux_kernel_status_page` can be probed. Pull the source,
point `KDIR` at your kernel, and build:

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

The packaged KernelSU `service.sh` loads the probe before switching MuMu
from its permissive boot default to enforcing mode. The next SELinux status
page access then repairs KernelSU's zeroed policyload metadata.

Unload:

```sh
su -c 'rmmod selinux_seqno_fix'
```

## Notes

- Requires `CONFIG_KPROBES` and `CONFIG_KRETPROBES`.
- Uses only a return probe on `selinux_kernel_status_page()`; the
  access-decision path is untouched.
- Supports arm64 and x86_64 Android kernels.
- If `selinux_kernel_status_page()` cannot be probed, the module refuses to
  load rather than guessing structure offsets.

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
