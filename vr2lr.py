#!/usr/bin/env python3
"""vr2lr: convert a PAN-OS legacy-routing config (network/virtual-router) to Advanced Routing Engine
(network/logical-router + network/routing-profile), offline.

Scope: virtual routers, interfaces, ECMP, administrative distances, IPv4/IPv6 static routes (next hop IP / IPv6 /
FQDN / next-vr / discard / interface-only, metric, admin distance, BFD, path monitoring), multicast-RIB static routes,
BFD profiles, the vsys import list, and IPv4 BGP (peer groups, peers, authentication, timers, import/export rules as
route-maps, redistribution of connected and static routes). OSPF, OSPFv3, RIP, multicast/PIM and the less common BGP
features are NOT converted: they are reported, and no output is written unless --allow-partial is given.

Usage:
  vr2lr.py <legacy-running-config.xml> [-o <out.xml>] [--report <report.txt>] [--allow-partial]

Output: the whole config with virtual-router replaced and deviceconfig/setting/advance-routing=yes, ready for
Device > Setup > Operations > Import + Load on the ARE firewall. Always validate before commit.
Python 3.8+, standard library only; nothing is sent anywhere.

vr2lr.html is the same converter for a web browser (no install). Both must give identical output and report
for every example; tools/parity.py checks that.

Exit codes: 0 ready (warnings possible), 1 input error, 2 items not converted (output written only with
--allow-partial).
"""
import argparse
import copy
import os
import re
import sys
import xml.etree.ElementTree as ET

__version__ = '0.3.0'

# legacy admin-dists key -> ARE admin-dists key(s). Legacy ospf-int covers intra- and inter-area routes.
ADMIN_DIST_MAP = {
    'static': ['static'], 'static-ipv6': ['static-ipv6'],
    'ospf-int': ['ospf-intra', 'ospf-inter'], 'ospf-ext': ['ospf-ext'],
    'ospfv3-int': ['ospfv3-intra', 'ospfv3-inter'], 'ospfv3-ext': ['ospfv3-ext'],
    'ibgp': ['bgp-internal'], 'ebgp': ['bgp-external'], 'rip': ['rip'],
}
# legacy defaults; an admin-dists value equal to its default is dropped so ARE applies its own default
ADMIN_DIST_DEFAULT = {'static': '10', 'static-ipv6': '10', 'ospf-int': '30', 'ospf-ext': '110', 'ospfv3-int': '30',
                      'ospfv3-ext': '110', 'ibgp': '200', 'ebgp': '20', 'rip': '120'}
PROTOCOL_NAMES = {'bgp': 'BGP', 'ospf': 'OSPF', 'ospfv3': 'OSPFv3', 'rip': 'RIP',
                  'redist-profile': 'a redistribution profile', 'redist-profile-ipv6': 'an IPv6 redistribution profile'}


class InputError(Exception):
    """The file is not something vr2lr can convert; the message is shown to the user as-is."""


class Report:
    def __init__(self):
        self.changes, self.checks, self.todos = [], [], []
        self.routers = self.converted = self.skipped = self.bgp_peers = 0
        self.hostname = self.version = ''

    def change(self, msg):
        self.changes.append(msg)

    def check(self, msg):
        self.checks.append(msg)

    def todo(self, msg):   # not converted: needs a human or a later version
        self.todos.append(msg)

    def text(self, in_name, out_name):
        n = lambda k, one, many: f'{k} {one if k == 1 else many}'
        if self.todos:
            result = (f'NOT READY - {n(len(self.todos), "item", "items")} could not be converted (see below). '
                      'Do not import this config until they are handled by hand.')
        elif self.checks:
            result = 'READY, WITH WARNINGS - read "Check these" below before you import.'
        else:
            result = 'READY - nothing needs your attention.'
        summary = (f'{n(self.routers, "virtual router", "virtual routers")} became '
                   f'{n(self.routers, "logical router", "logical routers")}. '
                   f'{n(self.converted, "static route", "static routes")} converted')
        summary += f', {self.skipped} not converted.' if self.skipped else '.'
        if self.bgp_peers:
            summary += f' {n(self.bgp_peers, "BGP peer", "BGP peers")} converted.'
        out = [f'vr2lr {__version__} conversion report', '',
               f'Input file : {in_name}',
               f'Firewall   : {self.hostname or "(no hostname)"} (PAN-OS {self.version or "unknown"})',
               f'Output file: {out_name}',
               f'Result     : {result}', '', summary]
        for title, items in (('Not converted - must be handled by hand', self.todos),
                             ('Check these', self.checks), ('What was changed', self.changes)):
            if items:
                out += ['', title] + [f'  - {m}' for m in items]
        out += ['', 'Next steps on the PA-520 (PAN-OS 12.1)',
                f'  1. Device > Setup > Operations > Import named configuration snapshot: choose {out_name}.',
                '     Keep that file name. PAN-OS only accepts names of up to 32 characters made of letters,',
                '     digits, ".", "_" and "-", so if your browser saved it as "... (1).xml", rename it first.',
                '  2. Load named configuration snapshot: choose the same file. This replaces the whole candidate',
                '     configuration of the PA-520 (management IP, hostname, admins, policies) with this one.',
                '  3. Commit > Validate Commit, and fix anything it reports.',
                '  4. Commit.',
                '  Encrypted values in the file (keys, passwords) only work if the PA-520 uses the same master',
                '  key as the PA-220.']
        return '\n'.join(out) + '\n'


def sub(parent, tag, text=None):
    e = ET.SubElement(parent, tag)
    if text is not None:
        e.text = text
    return e


def protocol_in_use(proto):
    """True when a legacy protocol block carries real config. Factory configs carry
    <bgp><enable>no</enable><dampening-profile>default...</bgp>, which is not in use."""
    if proto.findtext('enable') == 'yes':
        return True
    if proto.tag in ('redist-profile', 'redist-profile-ipv6'):
        return len(proto) > 0
    return any(c.tag not in ('enable', 'dampening-profile') for c in proto)


def convert_static(entry, fam, vr_name, rep, uni_out, mc_out):
    name = entry.get('name')
    dest = entry.findtext('destination')
    rt = entry.find('route-table')
    rib = rt[0].tag if rt is not None and len(rt) else 'unicast'
    if rib == 'no-install':
        rep.skipped += 1
        rep.check(f'Static route "{name}" ({dest}) in "{vr_name}" was NOT converted. It is set to "no-install" '
                  '(kept in the config but not used for forwarding), and Advanced Routing has no such setting. '
                  'Add it by hand on the PA-520 only if it should be an active route.')
        return
    if rib in ('unicast', 'both'):
        e = copy.deepcopy(entry)
        if e.find('route-table') is not None:
            e.remove(e.find('route-table'))
        nh = e.find('nexthop')
        if nh is not None and nh.find('next-vr') is not None:
            nh.find('next-vr').tag = 'next-lr'
        bfd = e.find('bfd/profile')
        if bfd is not None and bfd.text == 'Inherit-vr-global-setting':
            e.remove(e.find('bfd'))
            rep.check(f'Static route "{name}" ({dest}) in "{vr_name}" used BFD "Inherit-vr-global-setting", which '
                      'Advanced Routing does not have. The route was converted without BFD; add a BFD profile by '
                      'hand if it needs one.')
        uni_out.append(e)
    if rib in ('multicast', 'both'):
        if fam != 'ipv4':
            rep.todo(f'IPv6 static route "{name}" ({dest}) in "{vr_name}" is in the multicast routing table; '
                     'this version cannot convert it.')
            if rib == 'multicast':
                rep.skipped += 1
                return
        else:
            nh = entry.find('nexthop')
            ifc = entry.findtext('interface')
            if nh is None or nh.find('ip-address') is None or not ifc:
                rep.todo(f'Static route "{name}" ({dest}) in "{vr_name}" is in the multicast routing table but has '
                         'no interface or no next-hop IP address, which Advanced Routing requires for multicast '
                         'static routes. It was not converted.')
                if rib == 'multicast':
                    rep.skipped += 1
                    return
            else:
                m = sub(mc_out, 'entry')
                m.set('name', name)
                sub(m, 'destination', dest)
                sub(m, 'interface', ifc)
                sub(sub(m, 'nexthop'), 'ip-address', nh.findtext('ip-address'))
                if entry.findtext('admin-dist'):   # ARE multicast static: <preference> is the admin distance
                    sub(m, 'preference', entry.findtext('admin-dist'))
                was = 'the legacy multicast routing table; it is now a multicast static route' \
                    if rib == 'multicast' else \
                    'both legacy routing tables (unicast and multicast); it is now both a unicast and a multicast ' \
                    'static route'
                dropped = ' Its metric does not apply to multicast routes.' if entry.find('metric') is not None else ''
                rep.change(f'Static route "{name}" ({dest}) in "{vr_name}" was in {was}.{dropped}')
    rep.converted += 1


# ------------------------------------------------------------------ BGP ----------------------------------------------
# Legacy semantics verified at runtime on 10.2 and the mapping verified on 12.1.4 (see docs/mapping.md):
# - import/export rules apply per peer group (used-by); once a group has an enabled rule, unmatched routes are dropped,
#   which is the implicit deny of an ARE route-map. A group without rules accepts / advertises everything.
# - reject-default-route (absent = yes) drops a received default route; ARE has no such switch, so every peer group
#   gets the inbound prefix-list "reject-default-route".
# - allow-redist-default-route (absent = no) keeps 0.0.0.0/0 out of redistribution: a deny entry in each
#   redistribution route-map.
# - legacy redistributes "connect" routes but not loopback addresses; ARE does, so loopbacks get a deny entry.
# - legacy sends MED 0 for redistributed routes unless set-med is given; ARE sends the route metric, so set it to 0.
# - legacy "prepend N" makes the local AS appear N times in total; ARE aspath-prepend adds to the normal one: N-1.
# - legacy max-prefixes (default 5000) drops the excess; ARE can only warn or restart: warning-only is used.
NAME_MAX = 63   # ARE profile / filter / route-map names (12.1.4)
BGP_PEER_DEFAULTS = {'keep-alive-interval': '30', 'hold-time': '90', 'idle-hold-time': '15',
                     'min-route-adv-interval': '30', 'open-delay-time': '0'}


def fnv32(s):
    h = 0x811c9dc5
    for ch in s:
        h = ((h ^ ord(ch)) * 0x01000193) & 0xffffffff
    return format(h, '08x')


def nm(s):
    """An ARE object name of at most 63 characters; longer names are cut and made unique with a hash."""
    return s if len(s) <= NAME_MAX else s[:NAME_MAX - 9] + '-' + fnv32(s)


def el(tag, *children, text=None, **attrs):
    e = ET.Element(tag, attrs)
    if text is not None:
        e.text = text
    for c in children:
        if c is not None:
            e.append(c)
    return e


def members(tag, values):
    return el(tag, *[el('member', text=v) for v in values])


class Profiles:
    """ARE routing-profile objects shared by all logical routers, collected while converting and written once."""
    KINDS = ('auth', 'timer', 'af', 'filtering', 'redist', 'prefix', 'aspath', 'community', 'rm-bgp', 'rm-redist')

    def __init__(self):
        self.objs = {k: {} for k in self.KINDS}

    def add(self, kind, name, entry):
        entry.set('name', name)
        self.objs[kind].setdefault(name, entry)
        return name

    def prefix_list(self, name, rows):
        """rows: [(action, network | 'any', exact)] -> IPv4 prefix-list. exact=False matches the prefix and longer."""
        x = el('ipv4-entry')
        for i, (act, net, exact) in enumerate(rows, 1):
            p = el('prefix')
            if net == 'any':
                sub(p, 'network', 'any')
            else:
                pe = el('entry', el('network', text=net))
                if not exact:
                    sub(pe, 'less-than-or-equal', '32')
                p.append(pe)
            x.append(el('entry', el('action', text=act), p, name=str(i * 10)))
        return self.add('prefix', name, el('entry', el('type', el('ipv4', x))))

    def write(self, net):
        o = self.objs
        if not any(o.values()):
            return
        rp = net.find('routing-profile')
        if rp is None:
            rp = sub(net, 'routing-profile')
        groups = (('bgp', (('auth-profile', 'auth'), ('timer-profile', 'timer'), ('address-family-profile', 'af'),
                           ('filtering-profile', 'filtering'), ('redistribution-profile', 'redist'))),
                  ('filters', (('prefix-list', 'prefix'), ('as-path-access-list', 'aspath'),
                               ('community-list', 'community'))))
        for top, kinds in groups:
            node = None
            for tag, k in kinds:
                if o[k]:
                    node = node if node is not None else sub(rp, top)
                    sub(node, tag).extend(o[k].values())
            if top == 'filters' and (o['rm-bgp'] or o['rm-redist']):
                node = node if node is not None else sub(rp, 'filters')
                rms = sub(node, 'route-maps')
                if o['rm-bgp']:
                    sub(sub(rms, 'bgp'), 'bgp-entry').extend(o['rm-bgp'].values())
                if o['rm-redist']:
                    sub(sub(rms, 'redistribution'), 'redist-entry').extend(o['rm-redist'].values())


def rm_entry(seq, action, match=None, set_=None):
    return el('entry', el('action', text=action), match if match is not None and len(match) else None,
              set_ if set_ is not None and len(set_) else None, name=str(seq))


def match_prefix(name, where='address'):
    return el('ipv4', el(where, el('prefix-list', text=name)))


class BgpVr:
    """Converts one virtual router's protocol/bgp (+ the redistribution profiles it uses)."""

    def __init__(self, vr, profiles, rep):
        self.vr, self.p, self.rep = vr, profiles, rep
        self.name = vr.get('name')
        self.pfx = '' if self.name == 'default' else self.name + '-'
        self.bgp = vr.find('protocol/bgp')
        self.ok = True

    def todo(self, what):
        self.ok = False
        self.rep.todo(f'BGP in "{self.name}": {what} This version does not convert it; configure it by hand on '
                      'the PA-520.')

    def unknown(self, node, path, known):
        """Report child elements this version doesn't know (so nothing is dropped silently)."""
        for c in node:
            if c.tag not in known:
                self.todo(f'the setting "{path}/{c.tag}" is not supported.')

    # ---------------------------------------------------------------- global
    def convert(self):
        b, rep = self.bgp, self.rep
        self.unknown(b, 'bgp', ('enable', 'router-id', 'local-as', 'install-route', 'reject-default-route',
                                'allow-redist-default-route', 'ecmp-multi-as', 'enforce-first-as', 'routing-options',
                                'auth-profile', 'peer-group', 'policy', 'redist-rules', 'dampening-profile',
                                'global-bfd'))
        out = el('bgp')
        for t in ('enable', 'router-id', 'local-as', 'install-route', 'enforce-first-as', 'ecmp-multi-as'):
            if b.find(t) is not None:
                sub(out, t, b.findtext(t))
        ro = b.find('routing-options')
        if ro is not None:
            self.unknown(ro, 'routing-options', ('as-format', 'default-local-preference', 'graceful-restart', 'med',
                                                 'aggregate', 'reflector-cluster-id', 'confederation-member-as'))
            if ro.findtext('default-local-preference'):
                sub(out, 'default-local-preference', ro.findtext('default-local-preference'))
            gr = ro.find('graceful-restart')
            if gr is not None:
                self.unknown(gr, 'graceful-restart', ('enable', 'stale-route-time', 'local-restart-time',
                                                      'max-peer-restart-time'))
                out.append(copy.deepcopy(gr))
            med = ro.find('med')
            if med is not None:
                self.unknown(med, 'med', ('always-compare-med', 'deterministic-med-comparison'))
                out.append(copy.deepcopy(med))
            if ro.findtext('as-format') == '2-byte':
                rep.check(f'BGP in "{self.name}" used the 2-byte AS number format. Advanced Routing always uses '
                          '4-byte AS numbers; peers that only support 2-byte AS numbers still work (AS_TRANS).')
            for t in ('reflector-cluster-id', 'confederation-member-as'):
                if ro.findtext(t):
                    self.todo(f'"{t}" (route reflector / confederation) is set.')
        gb = b.findtext('global-bfd/profile')
        if gb:
            out.append(el('global-bfd', el('profile', text=gb)))
        used_damp = {x.text for x in b.findall('policy/import/rules/entry/action/allow/dampening')}
        for d in b.findall('dampening-profile/entry'):
            if d.get('name') != 'default' and d.get('name') not in used_damp:   # factory configs carry 'default'
                rep.change(f'BGP dampening profile "{d.get("name")}" in "{self.name}" was not carried over: no '
                           'import rule used it.')
        self.auth = {}
        for a in b.findall('auth-profile/entry'):
            n = self.p.add('auth', nm(self.pfx + a.get('name')), el('entry', copy.deepcopy(a.find('secret'))))
            self.auth[a.get('name')] = n
        if self.auth:
            rep.check(f'BGP authentication (MD5) secrets in "{self.name}" were carried over encrypted. They only work '
                      'if the PA-520 has the same master key as the PA-220.')
        self.reject_default = b.findtext('reject-default-route') != 'no'
        self.allow_redist_default = b.findtext('allow-redist-default-route') == 'yes'
        redist = self.redistribution()
        if redist:
            out.append(el('redistribution-profile', el('ipv4', el('unicast', text=redist))))
        self.policies()
        pgs = el('peer-group')
        self.limits = []
        for g in b.findall('peer-group/entry'):
            pgs.append(self.peer_group(g))
        if len(pgs):
            out.append(pgs)
        if self.limits:
            rep.check(f'BGP peers in "{self.name}" have a maximum number of prefixes ({", ".join(self.limits)}; '
                      '5000 is the PAN-OS 10.2 default). PAN-OS 10.2 dropped the prefixes above the limit; Advanced '
                      'Routing accepts them and logs a warning, as it has no "drop the excess" option.')
        for kind in ('conditional-advertisement', 'aggregation'):
            pol = b.find('policy/' + kind)
            if pol is not None and pol.find('.//entry') is not None:
                self.todo(f'{kind.replace("-", " ")} policies are configured.')
        n_groups = len(b.findall('peer-group/entry'))
        n_peers = len(b.findall('peer-group/entry/peer/entry'))
        rep.bgp_peers += n_peers
        rep.change(f'BGP in "{self.name}" (AS {b.findtext("local-as") or "?"}) converted: {n_groups} peer '
                   f'group{"" if n_groups == 1 else "s"}, {n_peers} peer{"" if n_peers == 1 else "s"}.')
        if self.reject_default:
            rep.change(f'BGP in "{self.name}" rejected a default route received from peers ("Reject Default Route"). '
                       'Advanced Routing has no such switch, so each peer group now has the inbound prefix list '
                       '"reject-default-route".')
        return out

    # ---------------------------------------------------------------- peer groups and peers
    def peer_group(self, g):
        gname = g.get('name')
        self.unknown(g, f'peer-group {gname}', ('enable', 'type', 'peer', 'aggregated-confed-as-path',
                                                'soft-reset-with-stored-info'))
        out = el('entry', name=gname)
        if g.find('enable') is not None:
            sub(out, 'enable', g.findtext('enable'))
        t = g.find('type')
        kind = t[0].tag if t is not None and len(t) else 'ebgp'
        af = {'soft': g.findtext('soft-reset-with-stored-info') == 'yes', 'self': False, 'private': False}
        if kind == 'ebgp':
            e = t.find('ebgp') if t is not None else None
            if e is not None:
                self.unknown(e, f'peer-group {gname}/type/ebgp', ('remove-private-as', 'import-nexthop', 'export-nexthop'))
                af['private'] = e.findtext('remove-private-as') == 'yes'
                af['self'] = e.findtext('export-nexthop') == 'use-self'
                if e.findtext('import-nexthop') == 'use-peer':
                    self.todo(f'peer group "{gname}" overrides the next hop of received routes with the peer address '
                              '("import next hop: use peer").')
        elif kind == 'ibgp':
            e = t.find('ibgp')
            self.unknown(e, f'peer-group {gname}/type/ibgp', ('export-nexthop',))
            af['self'] = e.findtext('export-nexthop') == 'use-self'
        else:
            self.todo(f'peer group "{gname}" is of type "{kind}" (confederation).')
            kind = 'ibgp' if kind == 'ibgp-confed' else 'ebgp'
        sub(sub(out, 'type'), kind)
        peers = g.findall('peer/entry')
        limits = [self.max_prefixes(p) for p in peers]
        group_limit = limits[0] if limits and all(x == limits[0] for x in limits) else '5000'
        af_name = self.af_profile(af, group_limit)
        sub(sub(out, 'address-family'), 'ipv4', af_name)
        filt = self.filtering_profile(gname)
        if filt:
            sub(sub(out, 'filtering-profile'), 'ipv4', filt)
        pe = sub(out, 'peer')
        for p, lim in zip(peers, limits):
            pe.append(self.peer(gname, p, None if lim == group_limit else (self.af_profile(af, lim), filt)))
        return out

    def max_prefixes(self, p):
        v = p.findtext('max-prefixes') or '5000'
        return '4294967295' if v == 'unlimited' else v

    def af_profile(self, af, limit):
        name = 'ipv4' + ('-nh-self' if af['self'] else '') + ('-rm-private' if af['private'] else '') \
            + ('-soft-reconfig' if af['soft'] else '') + ('' if limit == '5000' else
                                                         '-max-unlimited' if limit == '4294967295' else '-max' + limit)
        u = el('unicast', el('enable', text='yes'))
        if af['soft']:
            sub(u, 'soft-reconfig-with-stored-info', 'yes')
        if af['private']:
            sub(sub(u, 'remove-private-AS'), 'all')
        if af['self']:
            sub(sub(u, 'next-hop'), 'self')
        u.append(el('maximum-prefix', el('num_prefixes', text=limit), el('action', el('warning-only'))))
        return self.p.add('af', name, el('entry', el('ipv4', u)))

    def peer(self, gname, p, own_af):
        pname = p.get('name')
        where = f'peer {pname} (group {gname})'
        self.unknown(p, where, ('enable', 'peer-as', 'local-address', 'peer-address', 'connection-options', 'bfd',
                                'max-prefixes', 'enable-mp-bgp', 'address-family-identifier',
                                'subsequent-address-family-identifier', 'reflector-client', 'peering-type',
                                'enable-sender-side-loop-detection'))
        out = el('entry', name=pname)
        for t in ('enable', 'peer-as'):
            if p.find(t) is not None:
                sub(out, t, p.findtext(t))
        if own_af:
            no = sub(sub(out, 'inherit'), 'no')
            sub(sub(no, 'address-family'), 'ipv4', own_af[0])
            if own_af[1]:
                sub(sub(no, 'filtering-profile'), 'ipv4', own_af[1])
        la = p.find('local-address')
        if la is not None:
            self.unknown(la, where + '/local-address', ('interface', 'ip'))
            out.append(copy.deepcopy(la))
        pa = p.find('peer-address')
        if pa is not None:
            if pa.find('fqdn') is not None:
                self.todo(f'peer "{pname}" uses an FQDN peer address.')
            else:
                out.append(copy.deepcopy(pa))
        if p.findtext('enable-mp-bgp') == 'yes' or p.findtext('address-family-identifier') == 'ipv6':
            self.todo(f'peer "{pname}" uses MP-BGP / IPv6.')
        if p.findtext('subsequent-address-family-identifier/multicast') == 'yes' or \
                p.findtext('subsequent-address-family-identifier/unicast') == 'no':
            self.todo(f'peer "{pname}" exchanges multicast routes (SAFI multicast) or no unicast routes.')
        if p.findtext('reflector-client') not in (None, 'non-client'):
            self.todo(f'peer "{pname}" is a route reflector client.')
        if p.findtext('peering-type') not in (None, 'unspecified'):
            self.todo(f'peer "{pname}" uses peering type "{p.findtext("peering-type")}".')
        co = self.connection_options(pname, p.find('connection-options'))
        if co is not None:
            out.append(co)
        bfd = p.findtext('bfd/profile')
        if bfd:
            out.append(el('bfd', el('profile', text='Inherit-lr-global-setting'
                                    if bfd == 'Inherit-vr-global-setting' else bfd)))
        if p.find('enable-sender-side-loop-detection') is not None:
            sub(out, 'enable-sender-side-loop-detection', p.findtext('enable-sender-side-loop-detection'))
        lim = self.max_prefixes(p)
        if lim != '4294967295':
            self.limits.append(f'{pname} {lim}')
        return out

    def connection_options(self, pname, co):
        if co is None:
            return None
        self.unknown(co, f'peer {pname}/connection-options',
                     ('authentication', 'keep-alive-interval', 'hold-time', 'idle-hold-time', 'min-route-adv-interval',
                      'open-delay-time', 'multihop', 'incoming-bgp-connection', 'outgoing-bgp-connection'))
        out = el('connection-options')
        if co.findtext('authentication'):
            a = co.findtext('authentication')
            if a not in self.auth:
                self.todo(f'peer "{pname}" uses authentication profile "{a}", which does not exist.')
            else:
                sub(out, 'authentication', self.auth[a])
        tv = {k: co.findtext(k) or d for k, d in BGP_PEER_DEFAULTS.items()}
        if tv['idle-hold-time'] != '15':
            self.rep.check(f'BGP peer "{pname}" in "{self.name}" had idle hold time {tv["idle-hold-time"]} s. '
                           'Advanced Routing has no idle hold time; its reconnect retry interval (15 s) applies.')
        if any(tv[k] != BGP_PEER_DEFAULTS[k] for k in ('keep-alive-interval', 'hold-time', 'min-route-adv-interval',
                                                         'open-delay-time')):
            name = f'ka{tv["keep-alive-interval"]}-hold{tv["hold-time"]}' \
                + ('' if tv['min-route-adv-interval'] == '30' else f'-adv{tv["min-route-adv-interval"]}') \
                + ('' if tv['open-delay-time'] == '0' else f'-open{tv["open-delay-time"]}')
            t = el('entry')
            for k in ('keep-alive-interval', 'hold-time', 'min-route-adv-interval', 'open-delay-time'):
                if tv[k] != BGP_PEER_DEFAULTS[k]:
                    sub(t, k, tv[k])
            sub(out, 'timers', self.p.add('timer', name, t))
        if co.findtext('multihop') is not None:
            sub(out, 'multihop', co.findtext('multihop'))
        for d, port in (('incoming-bgp-connection', 'remote-port'), ('outgoing-bgp-connection', 'local-port')):
            x = co.find(d)
            if x is not None and (x.findtext('allow') == 'no' or (x.findtext(port) or '0') != '0'):
                self.todo(f'peer "{pname}" restricts {d.replace("-", " ")}s (allow / port).')
        return out if len(out) else None

    # ---------------------------------------------------------------- import / export rules -> route-maps
    def policies(self):
        self.route_maps = {}   # (group, 'in'|'out') -> route-map name
        rules_by_group = {}
        for direction, tag in (('in', 'import'), ('out', 'export')):
            for r in self.bgp.findall(f'policy/{tag}/rules/entry'):
                if r.findtext('enable') == 'no':
                    continue
                entry = self.rule(r, tag)
                for g in [m.text for m in r.findall('used-by/member')]:
                    rules_by_group.setdefault((g, direction), []).append(entry)
        for (g, direction), entries in rules_by_group.items():
            rm = el('route-map')
            for i, e in enumerate(entries, 1):
                e = copy.deepcopy(e)
                e.set('name', str(i * 10))
                rm.append(e)
            self.route_maps[(g, direction)] = self.p.add('rm-bgp', nm(f'{self.pfx}{g}-{direction}'), el('entry', rm))

    def rule(self, r, tag):
        rname = r.get('name')
        what = f'{tag} rule "{rname}"'
        base = nm(f'{self.pfx}{tag}-{rname}')
        self.unknown(r, what, ('enable', 'used-by', 'match', 'action'))
        match = el('match')
        m = r.find('match')
        if m is not None:
            self.unknown(m, what + '/match', ('address-prefix', 'as-path', 'community', 'extended-community', 'med',
                                              'nexthop', 'from-peer', 'route-table'))
            ips = el('ipv4')
            pfx = m.findall('address-prefix/entry')
            if pfx:
                self.p.prefix_list(base, [('permit', e.get('name'), e.findtext('exact') == 'yes') for e in pfx])
                ips.append(el('address', el('prefix-list', text=base)))
            nh = [x.text for x in m.findall('nexthop/member')]
            if nh:
                self.p.prefix_list(nm(base + '-nh'), [('permit', x if '/' in x else x + '/32', True) for x in nh])
                ips.append(el('next-hop', el('prefix-list', text=nm(base + '-nh'))))
            if len(ips):
                match.append(ips)
            if m.findtext('med'):
                sub(match, 'metric', m.findtext('med'))
            rx = m.findtext('as-path/regex')
            if rx:
                if not re.fullmatch(r'[0-9_^|\[,{}()\]$*+.?\\-]+', rx):
                    self.todo(f'{what} matches the AS path "{rx}", which uses characters Advanced Routing AS-path '
                              'lists do not accept.')
                else:
                    self.p.add('aspath', base, el('entry', el('aspath-entry', el(
                        'entry', el('action', text='permit'), el('aspath-regex', text=rx), name='10'))))
                    sub(match, 'as-path-access-list', base)
            rx = m.findtext('community/regex')
            if rx:
                lit = re.fullmatch(r'\^?(\d{1,5}:\d{1,5}|no-export|no-advertise|local-as|internet)\$?', rx)
                if not lit:
                    self.todo(f'{what} matches communities with the regular expression "{rx}"; only a single '
                              'literal community (such as 65000:100) is converted.')
                else:
                    self.p.add('community', base, el('entry', el('type', el('regular', el('regular-entry', el(
                        'entry', el('action', text='permit'), members('community', [lit.group(1)]), name='10'))))))
                    sub(match, 'regular-community', base)
            if m.findtext('extended-community/regex'):
                self.todo(f'{what} matches extended communities.')
            if m.find('from-peer/member') is not None:
                self.todo(f'{what} matches on the peer the route came from ("from peer").')
            rt = m.find('route-table')
            if rt is not None and len(rt) and rt[0].tag != 'unicast':
                self.todo(f'{what} matches the "{rt[0].tag}" route table.')
        a = r.find('action')
        if a is None or a.find('deny') is not None:
            return rm_entry(0, 'deny', match)
        allow = a.find('allow')
        st = el('set')
        if allow is not None:
            self.unknown(allow, what + '/action/allow', ('update', 'dampening'))
            if allow.findtext('dampening'):
                self.todo(f'{what} applies route-flap dampening.')
            u = allow.find('update')
            if u is not None:
                self.unknown(u, what + '/update', ('local-preference', 'med', 'origin', 'weight', 'community',
                                                   'extended-community', 'as-path', 'as-path-limit', 'nexthop'))
                if u.findtext('weight'):
                    sub(st, 'weight', u.findtext('weight'))
                if u.findtext('med'):
                    st.append(el('metric', el('action', text='set'), el('value', text=u.findtext('med'))))
                if u.findtext('local-preference'):
                    sub(st, 'local-preference', u.findtext('local-preference'))
                o = u.find('origin')
                if o is not None and len(o):
                    sub(st, 'origin', o[0].tag)
                c = u.find('community')
                if c is not None and len(c) and c[0].tag != 'none':
                    if c[0].tag in ('append', 'overwrite'):
                        if c[0].tag == 'overwrite':
                            sub(st, 'overwrite-regular-community', 'yes')
                        st.append(members('regular-community', [x.text for x in c[0].findall('member')]))
                    else:
                        self.todo(f'{what} removes communities ({c[0].tag}).')
                c = u.find('extended-community')
                if c is not None and len(c) and c[0].tag != 'none':
                    self.todo(f'{what} changes extended communities.')
                ap = u.find('as-path')
                if ap is not None and len(ap) and ap[0].tag != 'none':
                    if ap[0].tag == 'prepend' and tag == 'export':
                        n = int(ap[0].text or '0')
                        if n > 1:
                            st.append(members('aspath-prepend', [self.bgp.findtext('local-as')] * (n - 1)))
                    else:
                        self.todo(f'{what} changes the AS path ({ap[0].tag}).')
                if u.findtext('as-path-limit'):
                    self.rep.check(f'BGP {what} in "{self.name}" set the AS_PATHLIMIT attribute; Advanced Routing '
                                   'does not support it and it was dropped.')
                if u.findtext('nexthop'):
                    self.todo(f'{what} sets the next hop.')
        return rm_entry(0, 'permit', match, st)

    def filtering_profile(self, gname):
        u = el('unicast')
        if self.reject_default:
            self.p.prefix_list('reject-default-route', [('deny', '0.0.0.0/0', True), ('permit', 'any', False)])
            u.append(el('inbound-network-filters', el('prefix-list', text='reject-default-route')))
        rin, rout = self.route_maps.get((gname, 'in')), self.route_maps.get((gname, 'out'))
        if rin or rout:
            rms = sub(u, 'route-maps')
            if rin:
                sub(rms, 'inbound', rin)
            if rout:
                sub(rms, 'outbound', rout)
        if not len(u):
            return None
        return self.p.add('filtering', nm(self.pfx + gname), el('entry', el('ipv4', u)))

    # ---------------------------------------------------------------- redistribution
    def redistribution(self):
        rules = [r for r in self.bgp.findall('redist-rules/entry') if r.findtext('enable') != 'no']
        if not rules:
            return None
        profiles = {p.get('name'): p for p in self.vr.findall('protocol/redist-profile/entry')}
        used = []
        for r in rules:
            rname = r.get('name')
            what = f'redistribution rule "{rname}"'
            self.unknown(r, what, ('enable', 'address-family-identifier', 'route-table', 'set-origin', 'set-med',
                                   'set-local-preference', 'set-community', 'set-extended-community',
                                   'set-as-path-limit', 'metric'))
            if r.findtext('address-family-identifier') == 'ipv6':
                self.todo(f'{what} redistributes IPv6 routes.')
                continue
            rt = r.find('route-table')
            if rt is not None and len(rt) and rt[0].tag != 'unicast':
                self.todo(f'{what} redistributes into the "{rt[0].tag}" route table.')
            if r.findtext('set-extended-community/member'):
                self.todo(f'{what} sets extended communities.')
            if r.findtext('metric'):   # verified on 10.2: no effect on the MED or any attribute a peer receives
                self.rep.change(f'BGP {what} in "{self.name}" set "metric" {r.findtext("metric")}, which had no '
                                'effect on the routes PAN-OS 10.2 advertised (the MED comes from "set MED"). '
                                'It was not carried over.')
            if r.findtext('set-as-path-limit'):
                self.rep.check(f'BGP {what} in "{self.name}" set the AS_PATHLIMIT attribute; Advanced Routing does '
                               'not support it and it was dropped.')
            p = profiles.get(rname)
            if p is None:
                self.todo(f'{what} refers to redistribution profile "{rname}", which does not exist.')
                continue
            used.append((int(p.findtext('priority') or '0'), rname, p, r))
        used.sort(key=lambda x: (x[0], x[1]))
        loopbacks = [m.text for m in self.vr.findall('interface/member') if m.text.startswith('loopback')]
        maps = {}
        for src, legacy_type in (('connected', 'connect'), ('static', 'static')):
            entries = []
            if src == 'connected':
                entries += [rm_entry(0, 'deny', el('match', el('interface', text=lb))) for lb in loopbacks]
            if not self.allow_redist_default:
                entries.append(rm_entry(0, 'deny', el('match', match_prefix('default-route'))))
            n_permit, lists = 0, []
            for _, pname, p, r in used:
                types = [m.text for m in p.findall('filter/type/member')]
                if types and legacy_type not in types:
                    continue
                n_permit += p.find('action/no-redist') is None
                e, pls = self.redist_entries(pname, p, r)
                entries += e
                lists += pls
            if n_permit:   # only "no-redist" profiles apply: nothing of this type was redistributed
                if not self.allow_redist_default:
                    self.p.prefix_list('default-route', [('permit', '0.0.0.0/0', True)])
                for name, rows in lists:
                    self.p.prefix_list(name, rows)
                rm = el('route-map')
                for i, e in enumerate(entries, 1):
                    e.set('name', str(i * 10))
                    rm.append(e)
                maps[src] = self.p.add('rm-redist', nm(f'{self.pfx}{src}-to-bgp'),
                                       el('entry', el('connected-static', el('bgp', rm))))
        for _, pname, p, r in used:
            types = [m.text for m in p.findall('filter/type/member')]
            for t in types:
                if t not in ('connect', 'static'):
                    self.todo(f'redistribution profile "{pname}" redistributes {t} routes into BGP.')
        if not maps:
            return None
        u = el('unicast')
        for src in ('connected', 'static'):
            if src in maps:
                u.append(el(src, el('enable', text='yes'), el('route-map', text=maps[src])))
        if loopbacks and 'connected' in maps:
            self.rep.change(f'BGP in "{self.name}" redistributes connected routes. PAN-OS 10.2 did not include '
                            'loopback addresses in them, Advanced Routing does, so the loopback interfaces '
                            f'({", ".join(loopbacks)}) are excluded to keep the same routes advertised.')
        return self.p.add('redist', nm(self.pfx + 'redist'), el('entry', el('ipv4', u)))

    def redist_entries(self, pname, p, r):
        what = f'redistribution profile "{pname}"'
        f = p.find('filter')
        if f is not None:
            self.unknown(f, what + '/filter', ('type', 'interface', 'destination', 'nexthop', 'ospf', 'bgp'))
            for t in ('ospf', 'bgp'):
                if f.find(t) is not None and len(f.find(t)):
                    self.todo(f'{what} filters on {t.upper()} attributes.')
        base = nm(f'{self.pfx}redist-{pname}')
        ips, pls = el('ipv4'), []
        dst = [m.text for m in p.findall('filter/destination/member')]
        if dst:
            pls.append((base, [('permit', d, False) for d in dst]))
            ips.append(el('address', el('prefix-list', text=base)))
        nh = [m.text for m in p.findall('filter/nexthop/member')]
        if nh:
            pls.append((nm(base + '-nh'), [('permit', x if '/' in x else x + '/32', False) for x in nh]))
            ips.append(el('next-hop', el('prefix-list', text=nm(base + '-nh'))))
        action = 'deny' if p.find('action/no-redist') is not None else 'permit'
        st = el('set')
        if action == 'permit':
            o = r.findtext('set-origin')
            if o:
                sub(st, 'origin', o)
            st.append(el('metric', el('action', text='set'), el('value', text=r.findtext('set-med') or '0')))
            if r.findtext('set-local-preference'):
                sub(st, 'local-preference', r.findtext('set-local-preference'))
            comm = [m.text for m in r.findall('set-community/member')]
            if comm:
                st.append(members('regular-community', comm))
        ifcs = [m.text for m in p.findall('filter/interface/member')] or [None]
        out = []
        for ifc in ifcs:
            match = el('match')
            if ifc:
                sub(match, 'interface', ifc)
            if len(ips):
                match.append(copy.deepcopy(ips))
            out.append(rm_entry(0, action, match, copy.deepcopy(st)))
        return out, pls


def convert_vr(vr, rep, profiles):
    name = vr.get('name')
    rep.routers += 1
    n = sum(len(vr.findall(p + '/entry')) for p in ('routing-table/ip/static-route', 'routing-table/ipv6/static-route'))
    rep.change(f'Virtual router "{name}" is now logical router "{name}" ({n} static '
               f'route{"" if n == 1 else "s"} in the legacy config).')
    lr = ET.Element('entry', name=name)
    vrf = sub(sub(lr, 'vrf'), 'entry')
    vrf.set('name', 'default')
    ifs = vr.find('interface')
    if ifs is not None:
        vrf.append(copy.deepcopy(ifs))
    ad = vr.find('admin-dists')
    if ad is not None and len(ad):
        out = ET.Element('admin-dists')
        for c in ad:
            if c.text == ADMIN_DIST_DEFAULT.get(c.tag):
                continue
            for k in ADMIN_DIST_MAP.get(c.tag, []):
                sub(out, k, c.text)
            if c.tag not in ADMIN_DIST_MAP:
                rep.todo(f'Administrative distance "{c.tag}" in "{name}" has no known Advanced Routing equivalent.')
        if len(out):
            vrf.append(out)
            rep.change(f'Administrative distances in "{name}" carried over: '
                       + ', '.join(f'{c.tag} {c.text}' for c in out) + '.')
    ecmp = vr.find('ecmp')
    if ecmp is not None:
        vrf.append(copy.deepcopy(ecmp))   # same schema in both engines (verified 10.2 -> 12.1)
    rt = ET.Element('routing-table')
    mc = ET.Element('static-route')
    for fam, path in (('ipv4', 'routing-table/ip/static-route'), ('ipv6', 'routing-table/ipv6/static-route')):
        src = vr.find(path)
        if src is None or not len(src):
            continue
        out = ET.Element('static-route')
        for e in src.findall('entry'):
            convert_static(e, fam, name, rep, out, mc)
        if len(out):
            sub(rt, 'ip' if fam == 'ipv4' else 'ipv6').append(out)
    if len(rt):
        vrf.append(rt)
    if len(mc):
        sub(vrf, 'multicast').append(mc)
    proto = vr.find('protocol')
    if proto is not None:
        bgp = proto.find('bgp')
        if bgp is not None and protocol_in_use(bgp):
            vrf.append(BgpVr(vr, profiles, rep).convert())
        for p in proto:
            if p.tag == 'bgp' or p.tag == 'redist-profile' and bgp is not None and protocol_in_use(bgp):
                continue
            if protocol_in_use(p):
                rep.todo(f'"{name}" uses {PROTOCOL_NAMES.get(p.tag, p.tag)}. This version converts static routing '
                         'and BGP only; configure it by hand on the PA-520.')
    mcast = vr.find('multicast')
    if mcast is not None and mcast.findtext('enable') == 'yes':
        rep.todo(f'"{name}" has multicast routing (PIM/IGMP) enabled. This version does not convert it; configure '
                 'it by hand on the PA-520.')
    return lr


def convert(root, rep):
    """Convert in place. Raises InputError for files that are not a convertible firewall config."""
    if root.tag != 'config':
        raise InputError(f'This is not a PAN-OS configuration file (it starts with <{root.tag}>, not <config>).')
    if root.find('devices/entry/device-group') is not None or root.find('panorama') is not None:
        raise InputError('This looks like a Panorama configuration. Export the running configuration from the '
                         'PA-220 itself (Device > Setup > Operations > Export named configuration snapshot).')
    devs = root.findall('devices/entry')
    if not devs:
        raise InputError('This config has no device section (devices/entry). Export the running configuration '
                         'from the PA-220 (Device > Setup > Operations > Export named configuration snapshot).')
    rep.version = root.get('detail-version') or root.get('version') or ''
    if root.find('devices/entry/network/virtual-router') is None:
        if root.find('devices/entry/network/logical-router') is not None:
            raise InputError('This config already uses Advanced Routing (logical routers); there is nothing to '
                             'convert.')
        raise InputError('This config has no virtual routers, so there is no routing to convert.')
    for dev in devs:
        rep.hostname = rep.hostname or (dev.findtext('deviceconfig/system/hostname') or '')
        net = dev.find('network')
        vrs = net.find('virtual-router') if net is not None else None
        if vrs is None or not len(vrs):
            continue
        lrs = net.find('logical-router')
        if lrs is not None:
            net.remove(lrs)   # stub left by an earlier ARE toggle
            rep.change('Removed an empty or stale logical-router section before converting.')
        lrs = ET.Element('logical-router')
        profiles = Profiles()
        for vr in vrs.findall('entry'):
            lrs.append(convert_vr(vr, rep, profiles))
        idx = list(net).index(vrs)
        net.remove(vrs)
        net.insert(idx, lrs)
        # BFD profiles: network/profiles/bfd-profile -> network/routing-profile/bfd (same fields)
        bp = net.find('profiles/bfd-profile')
        if bp is not None and len(bp):
            rp = net.find('routing-profile')
            if rp is None:
                rp = sub(net, 'routing-profile')
            bfd = rp.find('bfd')
            if bfd is None:
                bfd = sub(rp, 'bfd')
            for e in bp.findall('entry'):
                bfd.append(copy.deepcopy(e))
            net.find('profiles').remove(bp)
            k = len(bp.findall('entry'))
            rep.change(f'{k} BFD profile{"" if k == 1 else "s"} moved to the routing profiles.')
        profiles.write(net)
        # vsys import lists: import/network/virtual-router -> import/network/logical-router
        for vsys in dev.findall('vsys/entry'):
            imp = vsys.find('import/network/virtual-router')
            if imp is not None:
                imp.tag = 'logical-router'
                rep.change(f'The {vsys.get("name")} import list now lists logical routers instead of virtual '
                           'routers.')
        # routing mode flag
        dc = dev.find('deviceconfig')
        if dc is None:
            dc = sub(dev, 'deviceconfig')
        st = dc.find('setting')
        if st is None:
            st = sub(dc, 'setting')
        ar = st.find('advance-routing')
        if ar is None:
            ar = sub(st, 'advance-routing')
        ar.text = 'yes'
        # anything else still pointing at a virtual router by tag name
        for parent in dev.iter():
            for c in parent:
                if 'virtual-router' in c.tag:
                    rep.todo(f'The config still has a <{c.tag}> element under <{parent.tag}> that refers to a '
                             'virtual router. Review it by hand.')
    return root


def out_name_for(in_name):
    """<input>-are.xml, made importable: PAN-OS (12.1.4, tested) accepts saved-config names of at most 32 characters
    from letters, digits, '.', '_' and '-', ending in .xml and not starting with '-'."""
    base = in_name.replace('\\', '/').rsplit('/', 1)[-1]
    stem = base[:-4] if base.lower().endswith('.xml') else base
    stem = re.sub(r'[^A-Za-z0-9._-]+', '-', stem).strip('-.')[:24].rstrip('-.') or 'converted'
    return stem + '-are.xml'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('input')
    ap.add_argument('-o', '--output')
    ap.add_argument('--report')
    ap.add_argument('--allow-partial', action='store_true',
                    help='write the output even when some items could not be converted')
    ap.add_argument('--version', action='version', version=__version__)
    a = ap.parse_args(argv)
    out = a.output or os.path.join(os.path.dirname(a.input), out_name_for(a.input))
    rep = Report()
    try:
        tree = ET.parse(a.input)
        convert(tree.getroot(), rep)
    except ET.ParseError as e:
        print(f'error: {a.input} is not valid XML ({e}). Is it the exported running configuration?', file=sys.stderr)
        return 1
    except (InputError, OSError) as e:
        print(f'error: {e}', file=sys.stderr)
        return 1
    text = rep.text(os.path.basename(a.input), os.path.basename(out))
    if a.report:
        with open(a.report, 'w', encoding='utf-8') as f:
            f.write(text)
    print(text, end='')
    if rep.todos and not a.allow_partial:
        print('No output file was written (use --allow-partial to write it anyway).', file=sys.stderr)
        return 2
    tree.write(out, encoding='utf-8', xml_declaration=False)
    print(f'wrote {out}')
    return 2 if rep.todos else 0


if __name__ == '__main__':
    sys.exit(main())
