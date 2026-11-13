"""Check that vr2lr.html (browser) and vr2lr.py (Python) give identical results.

Usage: parity.py [--keep DIR]

Runs every examples/*/*-legacy-*.xml plus synthetic edge cases through both implementations. The browser side
runs in headless Chromium: the page is copied with the input injected (base64) and a test hook in the page writes
the results into the DOM, which --dump-dom returns. Compared: the input-error message, the report text
(byte-identical) and the output XML (C14N 2.0 with whitespace stripped, so element order and content must match).
--keep DIR also writes each synthetic input and its Python output there (for graft-validate on 701).
Exit 0 when everything matches.
"""
import base64
import copy
import glob
import html
import json
import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
sys.path.insert(0, ROOT)
import vr2lr  # noqa: E402

PAGE = open(os.path.join(ROOT, 'vr2lr.html'), encoding='utf-8').read()
CHROME = next((c for c in ('chromium-browser', 'chromium', 'google-chrome') if subprocess.call(
    ['which', c], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0), None)


def run_py(text, name):
    rep = vr2lr.Report()
    try:
        root = ET.fromstring(text)
        vr2lr.convert(root, rep)
    except vr2lr.InputError as e:
        return {'error': str(e), 'report': None, 'xml': None}
    return {'error': None, 'report': rep.text(name, vr2lr.out_name_for(name)),
            'xml': ET.tostring(root, encoding='unicode')}


def run_js(text, name, tmp):
    b64 = base64.b64encode(text.encode('utf-8')).decode()
    inj = f'<body>\n<script type="text/plain" id="vr2lr-test-input" data-name="{html.escape(name)}">{b64}</script>'
    page = PAGE.replace('<body>', inj, 1)
    path = os.path.join(tmp, 'parity.html')
    open(path, 'w', encoding='utf-8').write(page)
    dom = subprocess.run([CHROME, '--headless', '--disable-gpu', '--no-first-run', '--dump-dom', 'file://' + path],
                         capture_output=True, text=True, timeout=120).stdout
    m = re.search(r'<pre id="vr2lr-test-output">(.*?)</pre>', dom, re.S)
    if not m:
        return {'error': 'NO TEST OUTPUT (page failed?)', 'report': None, 'xml': None}
    r = json.loads(html.unescape(m.group(1)))
    dec = lambda s: base64.b64decode(s).decode('utf-8') if s else None
    return {'error': r['error'], 'report': dec(r['report']), 'xml': dec(r['xml'])}


def c14n(x):
    return ET.canonicalize(xml_data=x, strip_text=True) if x else None


# ---------------------------------------------------------------- synthetic cases ----------------------------
def synthetic():
    base = open(os.path.join(ROOT, 'examples/static/static-legacy-10.2.xml'), encoding='utf-8').read()
    cases = {}

    def mutate(name, fn):
        root = ET.fromstring(base)
        fn(root)
        cases[name] = ET.tostring(root, encoding='unicode')

    def edge(root):
        dev = root.find('devices/entry')
        net = dev.find('network')
        vr = net.find('virtual-router/entry[@name="default"]')
        st = vr.find('routing-table/ip/static-route')
        # BFD inherit, multicast route without interface, both-RIB route with admin-dist
        e = copy.deepcopy(st.find('entry[@name="default-isp-b"]'))
        e.set('name', 'bfd-inherit')
        e.find('destination').text = '10.240.0.0/16'
        ET.SubElement(ET.SubElement(e, 'bfd'), 'profile').text = 'Inherit-vr-global-setting'
        st.append(e)
        e = copy.deepcopy(st.find('entry[@name="mcast-rpf-only"]'))
        e.set('name', 'mcast-no-ifc')
        e.remove(e.find('interface'))
        st.append(e)
        e = copy.deepcopy(st.find('entry[@name="both-ribs"]'))
        e.set('name', 'both-with-ad')
        ET.SubElement(e, 'admin-dist').text = '77'
        st.append(e)
        # IPv6 route in the multicast table is not valid in 10.2's schema, but test the branch anyway
        v6 = vr.find('routing-table/ipv6/static-route')
        e = copy.deepcopy(v6.find('entry[@name="v6-lan-servers"]'))
        e.set('name', 'v6-mcast')
        e.find('route-table').clear()
        ET.SubElement(e.find('route-table'), 'both')
        v6.append(e)
        # unknown admin distance key, stale logical-router stub, vsys import list
        ET.SubElement(vr.find('admin-dists'), 'future-proto').text = '99'
        ET.SubElement(net, 'logical-router')
        imp = ET.SubElement(ET.SubElement(dev.find('vsys/entry'), 'import'), 'network')
        ET.SubElement(ET.SubElement(imp, 'virtual-router'), 'member').text = 'default'
        # an enabled protocol, an enabled multicast block, a stray element named after virtual routers
        ET.SubElement(ET.SubElement(vr, 'protocol'), 'rip').append(ET.fromstring('<enable>yes</enable>'))
        ET.SubElement(ET.SubElement(vr, 'multicast'), 'enable').text = 'yes'
        ET.SubElement(dev.find('deviceconfig/system'), 'virtual-router-hint').text = 'x'
    mutate('synthetic-edge-cases', edge)

    def vsys_import_only(root):   # valid on 701: just the import list, nothing blocking
        dev = root.find('devices/entry')
        imp = ET.SubElement(ET.SubElement(dev.find('vsys/entry'), 'import'), 'network')
        ET.SubElement(imp, 'interface').extend(
            [ET.fromstring(f'<member>{i}</member>') for i in ('ethernet1/1', 'ethernet1/2')])
        vrm = ET.SubElement(imp, 'virtual-router')
        for n in ('default', 'guest'):
            ET.SubElement(vrm, 'member').text = n
    mutate('synthetic-vsys-import', vsys_import_only)

    def no_hostname_no_version(root):
        root.attrib.clear()
        h = root.find('devices/entry/deviceconfig/system/hostname')
        root.find('devices/entry/deviceconfig/system').remove(h)
    mutate('synthetic-no-hostname', no_hostname_no_version)

    are = open(os.path.join(ROOT, 'examples/static/static-are-12.1.xml'), encoding='utf-8').read()
    cases['error-already-are'] = are
    cases['error-not-config'] = '<response status="success"><result/></response>'
    cases['error-no-devices'] = '<config version="10.2.0"><shared/></config>'
    cases['error-panorama'] = '<config><panorama/><devices><entry name="localhost.localdomain"/></devices></config>'
    cases['error-no-vr'] = ('<config><devices><entry name="localhost.localdomain"><network><interface/></network>'
                            '</entry></devices></config>')
    return cases


def main():
    if not CHROME:
        sys.exit('no chromium/chrome found')
    keep = sys.argv[sys.argv.index('--keep') + 1] if '--keep' in sys.argv else None
    inputs = {os.path.basename(p): open(p, encoding='utf-8').read()
              for p in sorted(glob.glob(os.path.join(ROOT, 'examples/*/*-legacy-*.xml')))}
    syn = synthetic()
    inputs.update({k + '.xml': v for k, v in syn.items()})
    static = inputs['static-legacy-10.2.xml']
    for odd in ('Site 42 (1) #main running config for the big branch.xml', 'C:\\Users\\ops\\running-config.xml',
                '---.xml', 'running-config.XML', 'site-042_pa220.running-config.xml'):
        inputs[odd] = static
    bad = 0
    with tempfile.TemporaryDirectory() as tmp:
        for name, text in inputs.items():
            py, js = run_py(text, name), run_js(text, name, tmp)
            diffs = [k for k in ('error', 'report') if py[k] != js[k]]
            if c14n(py['xml']) != c14n(js['xml']):
                diffs.append('xml')
            status = 'error: ' + py['error'][:60] if py['error'] else f'{len(py["report"].splitlines())} report lines'
            print(('MATCH ' if not diffs else 'DIFF  ') + f'{name:42} {status}')
            for k in diffs:
                bad += 1
                print(f'   {k}:\n     py: {str(py[k])[:400]!r}\n     js: {str(js[k])[:400]!r}')
            if keep and name.endswith('.xml') and name[:-4] in syn and py['xml']:
                open(os.path.join(keep, name), 'w').write(text)
                open(os.path.join(keep, name[:-4] + '-are.xml'), 'w').write(py['xml'])
    print('all match' if not bad else f'{bad} difference(s)')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
