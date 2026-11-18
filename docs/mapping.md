# Legacy routing → Advanced Routing: mapping and test notes

How `vr2lr` maps a PAN-OS legacy-routing configuration (`network/virtual-router`) to the Advanced Routing Engine
(`network/logical-router` + `network/routing-profile`), and what was found while testing it.

Everything here was checked on two VM-Series lab firewalls: **PAN-OS 10.2.11-h1 in legacy mode** (the source) and
**PAN-OS 12.1.4 with Advanced Routing** (the target). "Verified" means the converted configuration validated and
committed on 12.1.4. The example configs in [`examples/`](../examples) are synthetic lab configs: no real network or
customer data.

## Static routing mapping (verified on 12.1.4)

| Legacy (10.2) | Advanced Routing (12.1) |
|---------------|-------------------------|
| `network/virtual-router/entry[X]` | `network/logical-router/entry[X]/vrf/entry[default]` |
| `interface`, `ecmp` | copied unchanged (all four ECMP algorithms, weights, hash seed) |
| `admin-dists` static / static-ipv6 / ospf-ext / ospfv3-ext / rip | same names |
| `admin-dists` ospf-int | `ospf-intra` + `ospf-inter` |
| `admin-dists` ospfv3-int | `ospfv3-intra` + `ospfv3-inter` |
| `admin-dists` ibgp / ebgp | `bgp-internal` / `bgp-external` |
| static route entry | same fields, minus `route-table` |
| `nexthop/next-vr` | `nexthop/next-lr` |
| `bfd`, `path-monitor` on a route | unchanged |
| `route-table unicast` | `routing-table` (unicast) |
| `route-table multicast` | `vrf/multicast/static-route` (destination, interface, next-hop IP only); admin distance → `preference` |
| `route-table both` | both places |
| `route-table no-install` | **no equivalent**: the route is skipped with a warning (it was not forwarding anyway) |
| `network/profiles/bfd-profile` | `network/routing-profile/bfd` (same fields) |
| `vsys/import/network/virtual-router` | `vsys/import/network/logical-router` |
| — | `deviceconfig/setting/advance-routing yes` |

Schema comparison (`type=config&action=complete`) of every static-routing node: 10.2 and 12.1.4 are identical apart
from `route-table` (legacy only), `next-vr` → `next-lr`, the split admin distances, and ARE-only extras that the
converter never needs to create (static `tag`, path-monitor `destination-fqdn` / `source-override`, multicast
`preference`). DHCP-client / PPPoE `create-default-route` has the same schema in both.

### Defaults when an element is absent
- Path monitoring: same runtime defaults in both (interval 3, count 5).
- ECMP: the values PAN-OS's own migrator treats as defaults (max-path 2, symmetric-return no, use-port no, WRR
  weight 100) match the documented 10.2 defaults. Low risk, not verified at runtime.

## PAN-OS's built-in migrator (for comparison)

PAN-OS 10.2 in legacy mode has an XML-API-drivable migrator:
`<request><routing><migrate-config/>|<show-config/>|<show-error/>|<delete-config/></routing></request>`.
It reads the committed running config and needs neither an engine switch nor a reboot. Its output, minus the
`virtual-router` block it keeps alongside, generally validates on 12.1.4. It only runs on a platform that supports
both engines, and it was **silently wrong** in these tested cases (`show-error` reported nothing):

- Every static route is renamed `<name>-ipv4-unicast` / `<name>-ipv6-unicast`.
- `no-install` routes (IPv4 and IPv6) become installed routes, which is a forwarding change.
- Multicast-RIB routes become unicast routes.
- ECMP weighted-round-robin interfaces on subinterfaces are renamed `ethernet1/7.31` → `ethernet1-7.31`, which then
  fails validation on 12.1 ("not a valid reference").
- `ospf-intra` / `ospfv3-intra` admin distances are dropped, and `ospfv3-inter` takes the IPv4 `ospf-int` value.
- Default-valued fields are dropped; disabled BGP/OSPF/RIP blocks and reject-default-route filters are added.

For a dynamic-routing config it did report these gaps: OSPF→BGP redistribution area / path-type filters dropped
(codes 10015/10016), BGP dampening profiles migrated with defaults and not attached (10000/10047), AS-path prepend in
an export rule unsupported (10022), OSPF stub default-route metric not converted (10013).

## Importing on the new firewall

- **Saved-config names** (probed on 12.1.4): at most 32 characters from `A-Z a-z 0-9 . _ -`, ending `.xml`, not
  starting with `-`. Spaces and `( ) # + @ , ~ =` are rejected, so a browser's duplicate download `name (1).xml` fails
  to import. The tool always produces a valid name.
- **Master key.** Encrypted values are carried over unchanged. With the default master key they commit as-is
  (verified: 10.2 ciphertext committed unchanged on 12.1.4). With a custom master key, set the **same** key on the new
  firewall before loading the config; otherwise the commit fails with "bad encryption or wrong masterkey" and the
  secrets must be re-entered. Hand-edited files can also corrupt ciphertext, so convert the file as exported.
  Sources: Palo Alto Networks knowledge base articles kA14u000000sZNrCAM and kA14u000000oNkMCAU.

## Test results

| Example | What it covers | Converter vs native ARE config |
|---------|----------------|--------------------------------|
| `static` | every static-route option | identical, except one unused BFD profile that really exists in the source |
| `static-ecmp` | three VRs: weighted / balanced round robin, IP hash | identical |
| `static-edge` | factory-shaped VR with disabled protocol stubs, all admin distances, IPv6 path-monitor / BFD / discard / next-vr / interface-only / no-install, multicast route with admin distance, DHCP default route, 31-character names | identical |
| `bgp-branch` | eBGP with MD5 / timers / max-prefix / import and export rules, eBGP over a tunnel with every default spelled out, iBGP with next-hop self, connected and static redistribution with priorities and no-redist, a second router peering with the first | identical; BGP tables identical at runtime |
| `kitchen-sink` | BGP, OSPF, redistribution | BGP partly converted; OSPF, dampening, aggregation, conditional advertisement reported (exit 2), as designed |

Every converted example validates on 12.1.4, both grafted onto a running config and as a whole-file import of the
bytes the browser saves. `tools/parity.py` confirms the browser and Python converters give byte-identical reports
and canonically identical XML on every example and on synthetic edge cases.

## BGP mapping (verified at runtime on 10.2.11 and 12.1.4)

BGP was tested with real sessions: two routers on the same firewall peer over loopbacks joined by next-vr / next-lr
static routes, so routes really flow even without connected links. The `bgp-branch` example was run on 10.2 in legacy
mode, converted, and run on 12.1.4. Both firewalls ended up with **identical BGP tables** (prefix, local or received,
AS path, local preference, MED) on both routers. The same check catches a deliberately introduced difference.

| Legacy (10.2) `protocol/bgp` | Advanced Routing (12.1) |
|------------------------------|-------------------------|
| enable, router-id, local-as, install-route, enforce-first-as, ecmp-multi-as | same, under `logical-router/.../vrf/bgp` |
| routing-options: default-local-preference, graceful-restart, med | `bgp/default-local-preference`, `bgp/graceful-restart`, `bgp/med` |
| routing-options/as-format 2-byte | always 4-byte (reported) |
| auth-profile | `routing-profile/bgp/auth-profile` (encrypted secret copied) |
| peer: keep-alive, hold, min-route-adv, open-delay | `routing-profile/bgp/timer-profile`, only when not the defaults (30/90/30/0) |
| peer: idle-hold-time | no equivalent; reconnect retry interval (15 s) applies (reported if not 15) |
| peer: local-address, peer-address, peer-as, multihop, BFD | same; BFD `Inherit-vr-global-setting` → `Inherit-lr-global-setting` |
| peer: max-prefixes (default 5000) | address-family profile `maximum-prefix`, warning-only (reported, see below) |
| peer group: type ebgp / ibgp | same; a peer group also needs an address-family profile (required by 12.1) |
| ebgp remove-private-as yes | address-family profile `remove-private-AS all` |
| export-nexthop use-self | address-family profile `next-hop self` |
| soft-reset-with-stored-info yes | address-family profile `soft-reconfig-with-stored-info` |
| import / export rules (per peer group via used-by) | one inbound and one outbound BGP route-map per peer group, rules in order |
| rule match: address-prefix (exact yes / no) | prefix-list entry (exact / `le 32`) |
| rule match: as-path regex, literal community, MED, next hop | AS-path access list, community list, `match metric`, next-hop prefix-list |
| rule action: deny / allow | route-map deny / permit |
| update: local-preference, MED, origin, weight, community append / overwrite | `set local-preference`, `set metric`, `set origin`, `set weight`, `set regular-community` (+ overwrite) |
| export update: as-path prepend N | `aspath-prepend` with **N-1** copies of the local AS (see below) |
| reject-default-route (absent = yes) | inbound prefix-list `reject-default-route` on every peer group |
| redist-profile + bgp redist-rules (connect, static) | redistribution profile with a route-map per source; profiles in priority order |
| redist filter: destination / interface / next hop | prefix-list (`le 32`) / `match interface` / next-hop prefix-list |
| redist-rules: set-origin, set-med, set-local-preference, set-community | route-map `set` (MED 0 when no set-med, see below) |
| allow-redist-default-route (absent = no) | deny entry for 0.0.0.0/0 at the top of each redistribution route-map |

### Legacy behaviour found by testing (and how the converter keeps it)

- **Import/export rules** apply per peer group. A group with no enabled rule accepts and advertises everything.
  Once a group has an enabled rule, a route that matches no rule is rejected (import) or not advertised (export).
  That is the same implicit deny an Advanced Routing route-map has. Disabled rules are ignored.
- **Reject default route** is on unless set to `no`, so a default route learned from a peer is dropped. Advanced
  Routing has no such switch; an inbound prefix-list on every peer group does the same.
- **Redistribution destinations** match the prefix and anything more specific (a `10.0.0.0/8` entry also
  redistributes `10.50.0.0/16`, and `0.0.0.0/0` matches everything).
- **Connected routes** don't include loopback addresses in legacy (they are host routes); Advanced Routing
  redistributes them. The converter adds a deny entry per loopback interface so the same routes are advertised.
- **MED of redistributed routes** is 0 in legacy unless `set-med` is given; Advanced Routing sends the route's metric
  (10 for a static route). The converter sets MED 0 explicitly.
- **AS-path prepend N** makes the local AS appear N times in total (prepend 1 changes nothing); Advanced Routing's
  `aspath-prepend` adds to the one copy every eBGP update gets, so N-1 copies are configured.
- The redistribution rule's **metric** field had no effect on anything a peer receives; it is dropped (reported).
- **Maximum prefixes:** legacy keeps the session up and silently drops prefixes above the limit (default 5000).
  Advanced Routing only has warning-only (accepts all and logs) or restart (resets the session); the default there is
  1000. The converter carries the legacy limit with warning-only and reports it.
- `multihop 0` works for directly reachable peers in both (TTL 1 for eBGP).
- **Remove private AS** (eBGP peer group): legacy strips the private AS numbers from the path it sends
  (`65000 65200` arrives as `65000`). `remove-private-AS all` does the same on Advanced Routing; verified with a
  three-router chain on both releases, using the converter's browser output.

### Not converted (reported as "Not converted" items)

MP-BGP / IPv6, FQDN peer addresses, confederations, route reflector settings, peering type, restricted incoming /
outgoing connections, import next hop "use peer", conditional advertisement, aggregation, dampening used by a rule,
community regular expressions other than a single literal community, extended communities, `from-peer` matches,
multicast route tables, next-hop and AS-path-remove updates, and redistribution of OSPF / RIP routes. Any BGP setting
the converter does not recognise is also reported rather than dropped.

### PAN-OS's built-in migrator on the same config

Loaded on 12.1.4, its output produced **12 differences** in the BGP tables against legacy, while `show-error` reported only
the AS-path prepend:

- the site no longer accepted the routes its AS-path rule allowed (10.50.0.0/16, 10.60.0.0/16);
- the tunnel subnet (connected) was no longer advertised;
- the AS-path prepend was dropped;
- the "no-redist" profile was ignored, so an extra /32 was advertised;
- redistributed static routes carried MED 10 instead of 0.

On the `kitchen-sink` example it also turned per-peer keep-alive / hold timers into an empty timer profile, lost the
max-prefixes value and reset dampening profiles to defaults without attaching them.

## Open items
- **no-install:** a possible ARE equivalent is a per-VRF `rib-filter` route-map denying the prefix, so it stays
  configured but out of the RIB. Untested; the converter skips such routes with a warning instead.
- **OSPF, OSPFv3, RIP and PIM** remain out of scope and are reported for manual work.
- **BGP remove-private-AS** with a path that mixes public and private AS numbers is untested: it needs four routers in
  a chain, and the platform allows three. Paths of private AS numbers only were verified (see above).
- Only 12.1.4 has been tested as a target.
