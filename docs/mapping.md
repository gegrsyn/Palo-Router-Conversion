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
| `kitchen-sink` | BGP, OSPF, redistribution | refused (exit 2) with a "Not converted" list, as designed |

Every converted example validates on 12.1.4, both grafted onto a running config and as a whole-file import of the
bytes the browser saves. `tools/parity.py` confirms the browser and Python converters give byte-identical reports
and canonically identical XML on every example and on synthetic edge cases.

## Open items
- **no-install:** a possible ARE equivalent is a per-VRF `rib-filter` route-map denying the prefix, so it stays
  configured but out of the RIB. Untested; the converter skips such routes with a warning instead.
- **Dynamic routing** (BGP, OSPF, redistribution, PIM) is out of scope and reported for manual work.
- Only 12.1.4 has been tested as a target.
