---
title: "IPV6_FRAG_ESCAPE — container escape tracking"
description: "Linux kernel IPv6 fragmentation overflow — unprivileged container escape — distro patch status tracker"
layout: "single"
date: 2026-07-03
lastmod: 2026-07-16
cover:
  image: "ipv6-frag-escape-tracker.png"
  alt: "IPV6_FRAG_ESCAPE — Linux IPv6 fragmentation container escape tracker"
  hiddenInSingle: true
---

## Summary

| Field | Detail |
|---|---|
| CVE ID | CVE-2026-53362 |
| Alias | `IPV6_FRAG_ESCAPE` (the name its [PoC][poc] uses); TuxCare writes it `ipv6-frag-escape` |
| Component | Kernel: `net/ipv6/ip6_output.c` `__ip6_append_data()` · IPv4 sibling `net/ipv4/ip_output.c` `__ip_append_data()` |
| Type | Container / jail escape → local privilege escalation — slab overflow into `skb_shared_info` → page UAF → Dirty Pagetable → root shell via `core_pattern` |
| Impact | Root-exploitable where `CONFIG_INIT_ON_ALLOC_DEFAULT_ON` is off (EL10); denial of service only where it is on (Debian/Ubuntu/NixOS) |
| Upstream fix | [`736b380e28d0`][fix6] (IPv6) + `eca856950f7c` (IPv4), merge [`38becddc`][merge]; first in **v7.2-rc1** |
| Introduced | `773ba4fe9104` (IPv6) / `8eb77cc73977` (IPv4) in v6.0 — dormant; armed by [`ce650a166335`][arm] in v6.6 |
| Affected window | Kernels **6.6 – 7.1** (reachable); ≥ 7.2 fixed; < 6.6 not reachable |
| Discoverer | Massimiliano Oldani ([`sgkdev`][poc]) |
| Public disclosure | 2026-06-29 ([LinkedIn][writeup]) / 2026-06-30 ([AlmaLinux][alma], [TuxCare][tuxcare], [Finnish NCSC][ncsc]) |
| Public PoC | [sgkdev/ipv6_frag_escape][poc] |
| KEV / EPSS / CVSS | Not yet assigned (CVE newly issued) |

## How the exploitation chain works

`__ip6_append_data()` builds an IPv6 datagram from a userspace socket.  An
unprivileged user can trigger the bug from **inside a network-isolated
container** via a UDPv6 socket using `MSG_MORE` together with
`MSG_SPLICE_PAGES` (the path enabled by [`ce650a166335`][arm] in v6.6).
The bad fragment-gap accounting undersizes the head allocation, so writing
the packet overflows the tail of its own `skb` object into the adjacent
`skb_shared_info` — giving the attacker control of the single `nr_frags`
byte.  When the `skb` is freed, `skb_release_data()` walks
`frags[0 .. nr_frags)` and `put_page()`s never-initialised entries: a page
**use-after-free**.

The PoC reclaims the freed page as a last-level page table
(**Dirty Pagetable**), building a physical read/write primitive, defeats
KASLR from the self-referencing `init_top_pgt` entry, resolves symbols
from `/sys/kernel/btf/vmlinux` and an in-process `kallsyms` parse, neuters
SELinux by patching `avc_denied`, and overwrites `core_pattern` to run a
handler as root in the host's initial namespaces — an interactive root
shell.

> :information_source: Whether a vulnerable kernel is a **root escape** or
> only a **denial of service** turns on `CONFIG_INIT_ON_ALLOC_DEFAULT_ON`.
> With it **off** (the EL10 default) the stale `nr_frags` pointer survives
> and the chain reaches root.  With it **on** (Debian, Ubuntu, NixOS) the
> freed slot is zeroed, so the same trigger only NULL-derefs — a kernel
> crash, not a takeover.  The PoC additionally needs 5-level paging (LA57)
> active, a world-readable `/sys/kernel/btf/vmlinux`, unprivileged user
> namespaces, and x86-64; it self-aborts on anything else (and on any
> `uname` release without `.el10`).  **The kernel backport is the only
> thing that flips a verdict here** — `init_on_alloc` decides root-vs-DoS
> and is recorded in prose, not as a column.

## Vulnerable commit range

| Commit | Role | Description |
|---|---|---|
| `773ba4fe9104` / `8eb77cc73977` | Introduced | *ipv6/ipv4: avoid partial copy for zc* (v6.0) — the bad fraggap accounting; dormant until a trigger existed. |
| [`ce650a166335`][arm] | Armed | *udp6: Fix `__ip6_append_data()`'s handling of MSG_SPLICE_PAGES* (v6.6) — made the miscalculation reachable from an unprivileged UDPv6 socket. |
| [`736b380e28d0`][fix6] / `eca856950f7c` | Fixed | *ipv6/ipv4: account for fraggap on the paged allocation path* — merged as [`38becddc`][merge] in **v7.2-rc1**. |

The reachable lifetime is therefore v6.6 (2026) through v7.1; kernels
6.0–6.5 carry the latent miscalculation but no trigger, and < 6.0 predates
it entirely.

## Upstream fixed versions

The fix went to Linus as **v7.2-rc1** with **no `Cc: stable`**.  A CVE
(**CVE-2026-53362**) was subsequently assigned by the kernel CNA, and the
backport has since landed in all maintained in-window stable lines:
**6.6.144**, **6.12.95**, **6.18.38**, and **7.1.3**.  7.0.y reached end of
life upstream without receiving the backport.  LTS lines that predate the
trigger (6.1 and older) are not exploitable; the CVE record includes a
6.1.177 fix for the latent accounting bug nonetheless.

| Branch | Status | Current | Notes |
|---|---|---|---|
| Linus mainline | :white_check_mark: Carries `736b380e28d0` | v7.2-rc1 | first fixed release; merge `38becddc` |
| 7.1.x | :white_check_mark: Carries `736b380e28d0` | 7.1.3 | in window; first fixed point release |
| 7.0.x | :x: Not backported | 7.0.14 | in window; EOL upstream |
| 6.18.x | :white_check_mark: Carries `736b380e28d0` | 6.18.38 | LTS; in window; first fixed point release |
| 6.12.x | :white_check_mark: Carries `736b380e28d0` | 6.12.95 | LTS; in window; first fixed point release |
| 6.6.x | :white_check_mark: Carries `736b380e28d0` | 6.6.144 | LTS; in window; first fixed point release; oldest reachable line |
| 6.1.x | :heavy_minus_sign: Not affected | 6.1.177 | LTS; trigger `ce650a166335` not present (< 6.6) |
| 5.15.x | :heavy_minus_sign: Not affected | 5.15.210 | predates the introducing commit |
| 5.10.x | :heavy_minus_sign: Not affected | 5.10.259 | predates the introducing commit |

When verifying a tree directly, the fixed function is
`__ip6_append_data()` in `net/ipv6/ip6_output.c` (and `__ip_append_data()`
in `net/ipv4/ip_output.c`); the fix adds the missing `fraggap` term on the
paged allocation path.

## Distribution status

The deciding fact per release is whether the **kernel** is in the 6.6–7.1
window *and* lacks the [`736b380e28d0`][fix6] backport.  A kernel outside
that window (or carrying the backport) is not exploitable.  Within it, the
verdict is `:x:` where `CONFIG_INIT_ON_ALLOC_DEFAULT_ON` is off (root
escape) and `:warning:` where it is on (denial of service only — a
mitigation, not a fix).  *Fixed since* records the date the kernel fix
first lands in that release.

The rows below track a focused set of distributions.  The EL10 family
(RHEL 10, CentOS Stream 10, Oracle Linux 10, CloudLinux OS 10) beyond the
Rocky/AlmaLinux row, and other systems named in the disclosures, appear
only in prose where relevant.

| Distribution | Release | Kernel | Fixed since | Status |
|---|---|---|---|---|
| Debian | sid (unstable) | 7.1.3-1 | 2026-07-05 | :white_check_mark: Fixed — ships 7.1.3 (carries upstream backport) |
| Debian | forky (testing) | 7.1.3-1 | 2026-07-11 | :white_check_mark: Fixed — ships 7.1.3 (carries upstream backport) |
| Debian | 13 (trixie) | 6.12.95-1 | 2026-07-05 | :white_check_mark: Fixed — ships 6.12.95 (carries upstream backport) |
| Debian | 12 (bookworm) | 6.1.170-3 | — | :white_check_mark: Not affected — trigger not present (< 6.6) |
| Debian | 11 (bullseye, LTS) | 5.10.223-1 | — | :white_check_mark: Not affected — predates the bug |
| Proxmox VE | 9 | 7.0.14-5-pve | 2026-07-16 | :white_check_mark: Fixed — ships 7.0.14-5-pve |
| Proxmox VE | 8 | 6.8.12-36-pve | 2026-07-16 | :white_check_mark: Fixed — ships 6.8.12-36-pve |
| NixOS | Unstable | 6.12.95 | 2026-07-06 | :white_check_mark: Fixed — ships 6.12.95 (carries upstream backport) |
| NixOS | 26.05 | 6.12.95 | 2026-07-08 | :white_check_mark: Fixed — ships 6.12.95 (carries upstream backport) |
| Rocky Linux | 10 | 6.12.0-211.32.1.el10_2 | 2026-07-11 | :white_check_mark: Fixed — ships 6.12.0-211.32.1.el10_2 (RLSA-2026:36956) |
| Rocky Linux | 9 | 5.14.0-687.17.1.el9_8 | — | :white_check_mark: Not affected — trigger not present (< 6.6) |
| Rocky Linux | 8 | 4.18.0-553.el8_10 | — | :white_check_mark: Not affected — predates the bug |
| Amazon Linux | 2023 (kernel 6.1) | 6.1.176-220.360 | — | :white_check_mark: Not affected — trigger not present (< 6.6) |
| Amazon Linux | 2023 (kernel6.12) | 6.12.94-123.176 | — | :x: Vulnerable — in-window, no ALAS |
| Amazon Linux | 2023 (kernel6.18) | 6.18.36-69.136 | — | :x: Vulnerable — in-window, no ALAS |
| Amazon Linux | 2 (kernel 4.14) | 4.14.355-284.737 | — | :white_check_mark: Not affected — predates the bug |
| Amazon Linux | 2 (kernel-5.10) | 5.10.259-258.1043 | — | :white_check_mark: Not affected — trigger not present (< 6.6) |
| Amazon Linux | 2 (kernel-5.15) | 5.15.210-148.245 | — | :white_check_mark: Not affected — trigger not present (< 6.6) |
{.distros}

### Debian / Proxmox VE

Debian ships `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y`, so its in-window kernels
carry the bug but the PoC's stale-pointer technique only crashes the kernel —
a denial of service, not root.  That is a default mitigation, **not** a fix
until the `736b380e28d0` backport ships.  **Debian sid** (unstable) shipped `linux 7.1.3-1`, which tracks upstream
7.1.3 and carries the backport — sid is now fixed.  **Debian trixie**
(stable) shipped `linux 6.12.95-1` to the `trixie-security` pocket on
2026-07-05, which tracks upstream 6.12.95 and carries the backport —
trixie is now fixed.  **Debian forky** (testing) migrated from 7.0.x
to `linux 7.1.3-1`, which carries the backport — forky is now fixed.
Debian 12 (6.1) and 11 (5.10) predate the v6.6 trigger and
are not affected.  Proxmox VE builds
Ubuntu-derived kernels with the same `init_on_alloc` default; PVE 9 (7.0
default) and PVE 8 (6.8 default) are in-window and were DoS-only until
patched — upstream 7.0.y reached end of life without the upstream backport,
so both series required an independent Proxmox cherry-pick.  On 2026-07-14
Proxmox committed the fix to `pve-kernel.git` (`proxmox-kernel-7.0
7.0.14-5` for PVE 9, `proxmox-kernel-6.8 6.8.12-35` for PVE 8); both are
now published to `pve-no-subscription` — PVE 9 as `7.0.14-5-pve` and PVE 8
as `6.8.12-36-pve` (one build past the staged `6.8.12-35-pve`, same fix
included).  Proxmox publishes kernel updates to the `pve-no-subscription`
repository first; the enterprise repository receives the same kernels later.

### NixOS

nixpkgs sets `INIT_ON_ALLOC_DEFAULT_ON = yes` in its kernel
`common-config.nix`, so in-window unpatched NixOS kernels are DoS-only.
**NixOS Unstable** ships `6.12.95` as its default LTS kernel
(`linuxPackages`), which carries the `736b380e28d0` backport — unstable is
fixed.  **NixOS 26.05** now ships `6.12.95` as its default LTS kernel and
`7.1.3` as `linuxPackages_latest` — both carry the backport, so 26.05 is
now fixed as well.

### Rocky Linux / RHEL family

The EL10 family is the root-exploitable case: `CONFIG_INIT_ON_ALLOC_DEFAULT_ON`
is **off** by default, `/sys/kernel/btf/vmlinux` is world-readable, and the
shipped 6.12 kernel is in-window — exactly the PoC's target (proven on
CentOS Stream 10 `6.12.0-242.el10` and RHEL 10 `6.12.0-228.el10`).
**AlmaLinux 10** is the leading indicator: it shipped the initial fix as
`kernel-6.12.0-211.28.2.el10_2` on 2026-06-30 (testing repo), and
production BaseOS now carries `kernel-6.12.0-211.29.1.el10_2` — above the
stated fixed version, so AlmaLinux 10 production appears patched.  Red Hat
has since fixed **RHEL 10** in RHSA-2026:34911
(`6.12.0-211.30.1.el10_2`).  **Rocky 10** has shipped
`6.12.0-211.32.1.el10_2` (RLSA-2026:36956, 2026-07-11), which exceeds
the RHEL fixed NVR `211.30.1.el10_2` and incorporates all prior fixes —
Rocky 10 is now fixed.  Oracle Linux 10 and CloudLinux OS 10 track RHEL.
Rocky 8 (4.18) and 9 (5.14) predate the bug and Red Hat marks RHEL 8/9
**Not affected**.

### Amazon Linux

The default AL2023 stream (`kernel`, 6.1.x) and AL2 (`kernel`, 4.14.x)
predate the v6.6 trigger and are not affected.  AL2023's opt-in
`kernel6.12` / `kernel6.18` streams **are** in-window; if selected they
carry the bug, with the root-vs-DoS outcome depending on Amazon's
`init_on_alloc` default for that stream (verify before relying on it).

## Detection

**Is the kernel in the affected window?**  The bug is reachable on
6.6 through 7.1 and fixed in 7.2; compare the running kernel against the
*Upstream fixed versions* table and your distro row above:

```bash
uname -r
```

**Is memory zeroed on allocation?**  This is what separates a root escape
(`off`) from a mere DoS (`on`).  `=y` means hardened to DoS-only:

```bash
grep CONFIG_INIT_ON_ALLOC_DEFAULT_ON /boot/config-$(uname -r)
```

A boot-time override wins over the compiled default — check the command
line (empty output means no override, so the compiled default applies):

```bash
grep -o 'init_on_alloc=[01]' /proc/cmdline
```

Fallback if `/boot/config-*` is unreadable and `CONFIG_IKCONFIG_PROC=y`:

```bash
zgrep CONFIG_INIT_ON_ALLOC_DEFAULT_ON /proc/config.gz
```

**Are unprivileged user namespaces available?**  The trigger runs from
inside an unprivileged userns; `0` means they are disabled:

```bash
sysctl user.max_user_namespaces
```

**Is 5-level paging (LA57) active?**  The PoC's page-table walk requires
it; output means the CPU exposes it:

```bash
grep -o '\bla57\b' /proc/cpuinfo | head -1
```

**Is kernel BTF world-readable?**  The exploit resolves struct offsets
from it:

```bash
ls -l /sys/kernel/btf/vmlinux
```

## Public PoC

The upstream PoC is in [sgkdev/ipv6_frag_escape][poc].  It targets el10
only (it aborts unless `uname -r` contains `.el10` and 5-level paging is
active).  Do **not** run it on a system you are not authorised to test.

## Mitigation

The real fix is a patched kernel (the `736b380e28d0` backport).  Until one
is installed, two interim measures each break the chain on their own.

### Enable heap zeroing (turns a root escape into DoS)

On EL / Fedora (grubby), set `init_on_alloc=1` and reboot:

```bash
sudo grubby --update-kernel=ALL --args="init_on_alloc=1"
```

```bash
sudo reboot
```

On Debian/Ubuntu, add `init_on_alloc=1` to `GRUB_CMDLINE_LINUX` in
`/etc/default/grub`, then:

```bash
sudo update-grub
```

This costs a small allocator overhead and needs a reboot.  It does **not**
close the hole — it downgrades a root escape to a denial of service.

### Disable unprivileged user namespaces (removes the trigger)

Blocks the container-side trigger outright:

```bash
sudo sysctl -w user.max_user_namespaces=0
```

Persist it via a drop-in:

```bash
echo 'user.max_user_namespaces = 0' | sudo tee /etc/sysctl.d/99-ipv6-frag-escape.conf
```

This breaks workloads that rely on unprivileged user namespaces — rootless
Podman/Docker, unprivileged LXC, `unshare(1)`, and browser/CI sandboxes.

### NixOS

NixOS already builds with `init_on_alloc` on (DoS-only).  To remove the
residual trigger, disable unprivileged user namespaces declaratively:

```nix
boot.kernel.sysctl."user.max_user_namespaces" = 0;
```

Apply with `nixos-rebuild switch`.

## Risk notes

- **Shared-kernel container hosts:** on EL10 hosts that allow unprivileged
  user namespaces, this is a host-root primitive from inside an otherwise
  isolated container — the headline risk.
- **Multi-user / CI runners:** any unprivileged local user can attempt it
  where the preconditions hold; self-hosted CI executing untrusted code is
  directly in scope.
- **Hardened-by-default distros:** Debian, Ubuntu, and NixOS ship
  `init_on_alloc=on`, so a vulnerable kernel there is a denial of service,
  not a takeover — still a crash an unprivileged user can trigger.  Treat
  it as mitigated, not fixed; the kernel hole remains until patched.
- **Stable backports now available (CVE-2026-53362):** the fix has landed
  in 6.6.144, 6.12.95, 6.18.38, and 7.1.3, but distro kernels that have
  not yet adopted one of those releases remain vulnerable.  Check the
  distribution row for your kernel.

## Verification log

*Last verified 2026-07-16.*

### Upstream

- The fix is `736b380e28d0` (*ipv6: account for fraggap on the paged
  allocation path*, Wongi Lee, 2026-06-16) plus its IPv4 sibling
  `eca856950f7c`, merged as `38becddc` and first released in **v7.2-rc1**
  (`git describe --contains` → `v7.2-rc1~29^2~66^2`).
- The trigger `ce650a166335` (*udp6: Fix `__ip6_append_data()`'s handling
  of MSG_SPLICE_PAGES*) is present in stable branches 6.6.y and newer and
  absent from 6.1.y — confirming the 6.6 reachability boundary.
- **CVE-2026-53362** assigned by the kernel CNA (confirmed via `vulns.git`
  `origin/master`; record keys on `736b380e28d0` / `eca856950f7c`).
- **Stable backports landed**: 6.6.144, 6.12.95, 6.18.38, and 7.1.3 all
  carry the fix (SHA-reference grep against `linux/stable`; SHAs confirmed
  against the `vulns.git` `.dyad`).  7.0.y reached end of life at 7.0.14
  without a backport.  6.1.177 also carries a fix for the latent accounting
  bug, though 6.1.y lacks the trigger and is not exploitable.  6.16.y
  (at v6.16.12) is an in-window short-lived stable branch not covered by
  the CVE dyad and confirmed unpatched.

### Distributions

- **Debian** (via the security tracker and dak `madison` API): unstable
  `7.1.3-1`, **trixie `6.12.95-1`** (shipped to `trixie-security` as
  DSA-6381-1, first seen 2026-07-05), and **forky `7.1.3-1`** (migrated from 7.0.13-1
  to 7.1.3-1 in testing, observed 2026-07-11) all carry the upstream
  backport → **all three fixed**.  bookworm shows as open in the security
  tracker (latent accounting bug; trigger absent in 6.1.x → not
  exploitable, row unchanged).  bullseye 5.10.223-1 predates the bug →
  not affected.
- **Proxmox VE** (via the `pve-no-subscription` `Packages` index and the
  `pve-kernel.git` packaging changelog): PVE 9 default is the 7.0 series
  (`proxmox-default-kernel` 2.1.0); PVE 8 default is the 6.8 series.  Both
  are Ubuntu-derived `init_on_alloc=y`.  On 2026-07-14 Proxmox committed
  the fix to `pve-kernel.git`: `proxmox-kernel-7.0 7.0.14-5` (master,
  changelog: "fix CVE-2026-53362: IPv6 fragementation handling overflow")
  and `proxmox-kernel-6.8 6.8.12-35` (bookworm-6.8, same entry).  Both
  are now in `pve-no-subscription`: PVE 9 as `7.0.14-5-pve`, PVE 8 as
  `6.8.12-36-pve` (one build past the staged `6.8.12-35-pve`, same fix
  included) — both fixed.  The enterprise repository is auth-gated and
  trails `pve-no-subscription`, so tracking keys on `pve-no-subscription`.
- **NixOS** (via the local nixpkgs clone): `common-config.nix` sets
  `INIT_ON_ALLOC_DEFAULT_ON = yes`.  **nixos-unstable** at `6.12.95`
  (default LTS) and `7.1.3` (`linuxPackages_latest`) — both carry the
  backport, fixed.  **nixos-26.05** advanced to `6.12.95` default LTS
  and `7.1.3` latest — both carry the backport, now fixed.
- **Rocky / RHEL family** (via the Red Hat security data API, Rocky errata
  API, and BaseOS repodata): Red Hat lists RHEL 8 and 9 `kernel` **Not
  affected** (they predate the bug), and **RHEL 10 fixed** in RHSA-2026:34911
  (`6.12.0-211.30.1.el10_2`; EUS in RHSA-2026:35840).  **Rocky 10 fixed** in
  RLSA-2026:36956 (`6.12.0-211.32.1.el10_2`, 2026-07-11) — the build exceeds
  the RHEL fixed NVR `211.30.1.el10_2` and incorporates all prior fixes
  including CVE-2026-53362.  Rocky 9 `5.14.0-687.17.1.el9_8` and Rocky 8
  `4.18.0-553.el8_10` predate the bug → not affected.
- **AlmaLinux** (leading indicator, via its blog and BaseOS repodata):
  initial fix `kernel-6.12.0-211.28.2.el10_2` on 2026-06-30 (testing repo);
  production BaseOS now carries `kernel-6.12.0-211.29.1.el10_2`, which
  exceeds the stated fixed version — AlmaLinux 10 production appears patched.
  Kitten 10 patch still pending per the 2026-06-30 blog.
- **Amazon Linux**: default AL2023 (6.1.x) and AL2 (4.14.x) predate the
  trigger → not affected; AL2023 opt-in `kernel6.12`/`kernel6.18` streams
  are in-window and unverified for `init_on_alloc`.

## References

| Source | URL |
|---|---|
| Discoverer writeup (Oldani) | <https://www.linkedin.com/pulse/ipv6fragescape-unprivileged-container-jail-escape-poc-oldani-xbewf/> |
| AlmaLinux advisory | <https://almalinux.org/blog/2026-06-30-ipv6-frag-escape/> |
| TuxCare analysis | <https://tuxcare.com/blog/ipv6-frag-escape-cve/> |
| Finnish NCSC advisory | <https://www.kyberturvallisuuskeskus.fi/fi/haavoittuvuudet/haavoittuvuus-2026-17> |
| Public PoC | <https://github.com/sgkdev/ipv6_frag_escape> |
| Kernel fix (IPv6) | <https://github.com/torvalds/linux/commit/736b380e28d0480c7bc3e022f1950f31fe53a7c5> |
| Kernel fix (IPv4) | <https://github.com/torvalds/linux/commit/eca856950f7cb1a221e02b99d758409f2c5cec42> |
| Fix merge | <https://github.com/torvalds/linux/commit/38becddc332c1dbee6ab8dc8f13a860c6280b905> |
| Trigger commit | <https://github.com/torvalds/linux/commit/ce650a1663354a6cad7145e7f5131008458b39d4> |
| CVE-2026-53362 | <https://www.cve.org/CVERecord?id=CVE-2026-53362> |
| Debian DSA-6381-1 | <https://www.debian.org/security/2026/dsa-6381> |
{.references}

[writeup]: https://www.linkedin.com/pulse/ipv6fragescape-unprivileged-container-jail-escape-poc-oldani-xbewf/
[alma]: https://almalinux.org/blog/2026-06-30-ipv6-frag-escape/
[tuxcare]: https://tuxcare.com/blog/ipv6-frag-escape-cve/
[ncsc]: https://www.kyberturvallisuuskeskus.fi/fi/haavoittuvuudet/haavoittuvuus-2026-17
[poc]: https://github.com/sgkdev/ipv6_frag_escape
[fix6]: https://github.com/torvalds/linux/commit/736b380e28d0480c7bc3e022f1950f31fe53a7c5
[merge]: https://github.com/torvalds/linux/commit/38becddc332c1dbee6ab8dc8f13a860c6280b905
[arm]: https://github.com/torvalds/linux/commit/ce650a1663354a6cad7145e7f5131008458b39d4
