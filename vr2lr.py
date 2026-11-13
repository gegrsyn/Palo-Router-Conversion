#!/usr/bin/env python3
"""vr2lr: convert a PAN-OS legacy-routing config (network/virtual-router) to Advanced Routing Engine
(network/logical-router + network/routing-profile), offline.

Scope (static routing): virtual routers, interfaces, ECMP, administrative distances, IPv4/IPv6 static routes
(next hop IP / IPv6 / FQDN / next-vr / discard / interface-only, metric, admin distance, BFD, path monitoring),
multicast-RIB static routes, BFD profiles and the vsys import list. Dynamic routing (BGP, OSPF, OSPFv3, RIP,
redistribution profiles, multicast/PIM) is NOT converted: it is reported, and no output is written unless
--allow-partial is given.

Usage:
  vr2lr.py <legacy-running-config.xml> [-o <out.xml>] [--report <report.txt>] [--allow-partial]

Output: the whole config with virtual-router replaced and deviceconfig/setting/advance-routing=yes, ready for
Device > Setup > Operations > Import + Load on the ARE firewall. Always validate before commit.
Python 3.8+, standard library only; nothing is sent anywhere.

vr2lr.html is the same converter for a web browser (no install). Both must give identical output and report
for every example; lab/parity.py checks that.

Exit codes: 0 ready (warnings possible), 1 input error, 2 items not converted (output written only with
--allow-partial).
"""
import argparse
import copy
import os
import re
import sys
import xml.etree.ElementTree as ET

__version__ = '0.2.0'

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
        self.routers = self.converted = self.skipped = 0
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


def convert_vr(vr, rep):
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
        for p in proto:
            if protocol_in_use(p):
                rep.todo(f'"{name}" uses {PROTOCOL_NAMES.get(p.tag, p.tag)}. This version converts static routing '
                         'only; configure it by hand on the PA-520.')
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
        for vr in vrs.findall('entry'):
            lrs.append(convert_vr(vr, rep))
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
