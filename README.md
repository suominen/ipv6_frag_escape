# IPV6_FRAG_ESCAPE — Linux IPv6 fragmentation container escape tracking site

Patch-status tracker for **IPV6_FRAG_ESCAPE**, an unprivileged
container-to-host-root escape in the Linux kernel.  An arithmetic error in
the IPv6 fragmentation path (`__ip6_append_data()`, with an IPv4 sibling in
`__ip_append_data()`) undersizes an allocation so the packet's own head
object overflows into the trailing `skb_shared_info`, giving an attacker
control of `nr_frags` — a page use-after-free that the PoC converts into a
Dirty-Pagetable read/write primitive and finally a host-init-namespace root
shell via a `core_pattern` overwrite.  Discovered by Massimiliano Oldani
and [disclosed on 2026-06-29](https://www.linkedin.com/pulse/ipv6fragescape-unprivileged-container-jail-escape-poc-oldani-xbewf/).
Public PoC: <https://github.com/sgkdev/ipv6_frag_escape>.

The bad accounting was introduced dormant in v6.0 (`773ba4fe9104` IPv6 /
`8eb77cc73977` IPv4), made triggerable in v6.6 (`ce650a166335`), and fixed
in v7.2-rc1 by
[`736b380e28d0`](https://github.com/torvalds/linux/commit/736b380e28d0)
(merge [`38becddc`](https://github.com/torvalds/linux/commit/38becddc);
IPv4 sibling `eca856950f7c`).  The practical exploitable window is kernels
**6.6 through 7.1**; distro adoption of the backport is tracked below.

There is **no CVE** and, at disclosure, no `Cc: stable` — stable 6.6.y /
6.12.y did not automatically carry the backport, so each distribution picks
it up independently.  Whether a still-vulnerable kernel is a full root
escape or only a denial of service turns on
`CONFIG_INIT_ON_ALLOC_DEFAULT_ON`: it is **off** on EL10 (root-exploitable)
and **on** on Debian/Ubuntu (DoS-only).

The rendered site is published at
**<https://kimmo.cloud/ipv6_frag_escape/>**.  Deployment plan and current
setup state live in [`WEBSITE.md`](WEBSITE.md).

## Source of truth

The tracker is a single Hugo page: [`site/content/_index.md`](site/content/_index.md).
Edit that file; everything else is build infrastructure.

## Local development

Requires Hugo extended (≥ 0.146.0) and Go (for Hugo Modules to fetch the
PaperMod theme).

### With Nix (recommended)

```sh
nix develop          # dev shell: hugo, go, git, resvg
cd site
hugo server          # local preview at http://localhost:1313/ipv6_frag_escape/
```

If you use [direnv](https://direnv.net/), `direnv allow` once and the
dev shell auto-activates whenever you `cd` into the repo.

### Without Nix

Install Hugo extended ≥ 0.146.0 and Go ≥ 1.24 yourself, then:

```sh
cd site
hugo server          # http://localhost:1313/ipv6_frag_escape/
```

## Build and publish

```sh
make build       # local build into site/public/
make dist        # build, then rsync to haig:/ipv6_frag_escape/
make banner      # re-rasterise the social banner SVG → PNG (needs resvg + Roboto)
```

`make dist` runs `make build` first.  `make banner` is only needed after
editing `site/assets/ipv6-frag-escape-tracker.svg`; the rendered PNG is
committed.

## Repo layout

```
.
├── flake.nix              # Nix dev environment (hugo, go, git, resvg + RPM tools)
├── .envrc                 # direnv hook → `use flake`
├── .gitignore
├── Makefile               # `make build`, `make dist`, `make banner`
├── LICENSE                # CC BY 4.0
├── README.md              # this file
├── CLAUDE.md              # project instructions for Claude Code
├── WEBSITE.md             # publication plan / decisions log
├── scripts/               # auto-update agent: prompt + driver
├── systemd/               # user-level timer + service units
└── site/                  # Hugo project
    ├── hugo.toml
    ├── content/
    │   └── _index.md      # the tracker (single page)
    ├── assets/css/extended/custom.css       # PaperMod CSS overrides
    ├── assets/ipv6-frag-escape-tracker.svg  # social-banner source (→ make banner)
    ├── static/ipv6-frag-escape-tracker.png  # rendered OpenGraph banner (committed)
    ├── layouts/partials/  # PaperMod overrides (post_meta, extend_footer)
    ├── go.mod, go.sum     # Hugo Modules — pulls PaperMod theme
    └── …                  # standard Hugo skeleton
```

## License

[CC BY 4.0](LICENSE) — share and adapt with attribution.
