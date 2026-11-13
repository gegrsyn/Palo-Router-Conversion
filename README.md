# Palo Router Conversion (vr2lr)

Converts the routing in a PAN-OS firewall configuration from the **legacy routing engine** (virtual routers) to the
**Advanced Routing Engine** (logical routers), so a configuration exported from a legacy-only firewall can be loaded on
an Advanced-Routing-only firewall.

Built for replacing older models (e.g. PA-220 on PAN-OS 10.2, legacy routing only) with newer ones (e.g. PA-520 on
PAN-OS 12.1, Advanced Routing only). Neither box can switch engines, so the exported config has to be converted.

- **`vr2lr.html`**: the whole tool in one file. Open it in a browser, drop in `running-config.xml`, and download the
  converted config and a plain-language report. It works offline and needs no install. Its Content-Security-Policy
  stops it from making any network request, so the config never leaves your machine.
- **`vr2lr.py`**: the same converter as a command-line tool (Python 3.8+, standard library only).

> **Not an official Palo Alto Networks tool.** It is provided as-is, with no warranty and no support. Always run
> *Validate Commit* on the new firewall and check the result before you commit. PAN-OS and Palo Alto Networks are
> trademarks of Palo Alto Networks, Inc.

## Scope

| Converted | Not converted (reported, must be done by hand) |
|-----------|-----------------------------------------------|
| Static routes, IPv4 and IPv6 (next hop IP / FQDN / next-VR → next-LR / discard / interface-only) | BGP, OSPF, OSPFv3, RIP |
| Admin distances (split into the ARE per-protocol form) | Redistribution profiles |
| ECMP (all four algorithms) | Multicast routing (PIM / IGMP) when enabled |
| BFD profiles (moved to `routing-profile/bfd`) | |
| Path monitoring | |
| Multicast-RIB static routes (admin distance → `preference`) | |
| vsys `import/network/virtual-router` lists | |

Static routes set to `no-install` are skipped with a warning (READY WITH WARNINGS): ARE has no such setting, and
the route was not forwarding anyway.

Everything outside routing (interfaces, zones, policies, objects, device settings) is left untouched.

If a config contains anything that is not converted, the result is **NOT READY**. The browser keeps the download
locked until you confirm you will handle those items by hand (the CLI equivalent is `--allow-partial`).

## How to use it (per firewall)

1. **Old firewall:** *Device > Setup > Operations > Export named configuration snapshot* → `running-config.xml`.
2. **Convert:** open `vr2lr.html` and drop the file in. Read the result, then download the converted config (and
   the report).
3. **New firewall:** *Import named configuration snapshot* → *Load named configuration snapshot* → *Validate Commit*
   → *Commit*.

Things to know:

- **Keep the output file name.** PAN-OS 12.1 only imports names of 32 characters or fewer, made of
  `A-Z a-z 0-9 . _ -`. The tool always produces a valid name, but a browser's duplicate download such as
  `running-config-are (1).xml` is rejected, so rename such a file back before importing.
- **Master key.** Encrypted values (BGP/OSPF secrets, IPsec PSKs and so on) are carried over unchanged. With the
  default master key they commit as-is (tested). If the old firewall uses a custom master key, set the **same**
  master key on the new firewall *before* loading the config. Otherwise the commit fails with "bad encryption or
  wrong masterkey" and the secrets must be re-entered.

## Command line

    python3 vr2lr.py running-config.xml [-o out.xml] [--report report.txt] [--allow-partial]

Exit codes: `0` ready, `1` input error (not a firewall config, a Panorama export, already on Advanced Routing, …),
`2` some items not converted.

## Why not PAN-OS's built-in migrator?

PAN-OS has `request routing migrate-config`, but it only runs on a box that supports both engines. Its output was also
silently wrong in several cases tested here:

- Every route is renamed with an `-ipv4-unicast` / `-ipv6-unicast` suffix.
- `no-install` routes become installed routes.
- Multicast-RIB routes become unicast routes.
- ECMP weighted-round-robin on subinterfaces is renamed `ethernet1-7.31`, which fails validation on 12.1.
- The OSPF intra-area admin distances are dropped, and `ospfv3-inter` takes the IPv4 value.

Details, and the full legacy → ARE mapping table (verified by committing on 12.1.4), are in
[`docs/mapping.md`](docs/mapping.md).

## Repository layout

| Path | What it is |
|------|------------|
| `vr2lr.html` | Browser tool (the deliverable). Its JS core is a line-for-line port of `vr2lr.py`. |
| `vr2lr.py` | Reference converter and CLI. |
| `examples/<feature>/` | Synthetic lab configs (no real customer data). `*-legacy-10.2.xml` is an input; `*-are-12.1.xml` is the same intent configured natively on ARE (the expected output); `*-vendor-*` is the built-in migrator's output, for comparison. Admin password hashes are redacted; other secrets are lab dummies. |
| `tools/parity.py` | Runs every example and synthetic edge case through both converters and checks they agree (needs Chromium). |
| `tools/compare.py` | Semantic diff of the logical-router + routing-profile sections of two configs. |
| `docs/mapping.md` | Mapping table, test results, findings. |

## Verification

    python3 tools/parity.py                                            # browser == Python on every example and edge case (needs Chromium)
    python3 vr2lr.py examples/static-edge/static-edge-legacy-10.2.xml -o /tmp/out.xml
    python3 tools/compare.py /tmp/out.xml examples/static-edge/static-edge-are-12.1.xml   # converter vs native ARE

Current results: `static-ecmp` and `static-edge` match the native ARE configs exactly. Every converted example
validates on PAN-OS 12.1.4, including the file exactly as the browser saves it. The browser and Python outputs are
identical on every test input.

Tested target: PAN-OS 12.1.4. Other 12.1.x releases are expected to behave the same but are untested.

## License

[MIT](LICENSE)
