"""Semantic diff of the ARE routing sections of two configs (logical-router + routing-profile).
Entries are matched by name, element order and whitespace are ignored. Usage: compare.py <a.xml> <b.xml>"""
import sys
import xml.etree.ElementTree as ET


def flat(e, path, out):
    kids = list(e)
    if not kids:
        out[path] = (e.text or '').strip()
        return
    for c in kids:
        key = f"{c.tag}[{c.get('name')}]" if c.get('name') is not None else c.tag
        flat(c, f'{path}/{key}', out)


def routing(f):
    net = ET.parse(f).getroot().find('devices/entry/network')
    out = {}
    for t in ('logical-router', 'routing-profile'):
        e = net.find(t)
        if e is not None:
            flat(e, t, out)
    return out


a, b = routing(sys.argv[1]), routing(sys.argv[2])
only_a = sorted(set(a) - set(b))
only_b = sorted(set(b) - set(a))
diff = sorted(k for k in set(a) & set(b) if a[k] != b[k])
for k in only_a:
    print('- only in A:', k, '=', a[k])
for k in only_b:
    print('+ only in B:', k, '=', b[k])
for k in diff:
    print('~ differs  :', k, ':', a[k], '!=', b[k])
print(f'{len(a)} leaves in A, {len(b)} in B; {len(only_a)} only-A, {len(only_b)} only-B, {len(diff)} differ')
