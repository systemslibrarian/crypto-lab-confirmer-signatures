"""Play the real cryptography, keyboard controls, export and evidence at two widths."""
import http.server
import json
import subprocess
import sys
import threading
import unittest
from pathlib import Path
from playwright.sync_api import sync_playwright, expect
ROOT=Path(__file__).resolve().parents[1]
class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self,*args,**kwargs):super().__init__(*args,directory=str(ROOT),**kwargs)
    def log_message(self,*args):pass
class Server(http.server.ThreadingHTTPServer):daemon_threads=True
class RealPairingBrowser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert (ROOT/'dist/real/index.html').is_file(),'Build research/real-pairing first'
        cls.server=Server(('127.0.0.1',0),Handler)
        threading.Thread(target=cls.server.serve_forever,daemon=True).start()
        cls.origin=f'http://127.0.0.1:{cls.server.server_address[1]}/dist/real/'
        cls.pw=sync_playwright().start();cls.browser=cls.pw.chromium.launch()
        (ROOT/'test-results').mkdir(exist_ok=True)
    @classmethod
    def tearDownClass(cls):
        cls.browser.close();cls.pw.stop();cls.server.shutdown()
    def access(self,page):
        self.assertTrue(page.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Horizontal overflow')
        result=page.evaluate("""async()=>await axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa','best-practice']}})""")
        self.assertEqual(result['violations'],[],json.dumps(result['violations'],indent=2))
    def complete(self,page,kind):
        expect(page.locator('#challenge')).to_be_disabled()
        expect(page.locator('#answer')).to_be_disabled()
        page.locator('#begin-'+kind).click()
        expect(page.locator('#challenge')).to_be_enabled(timeout=30000)
        expect(page.locator('#answer')).to_be_disabled()
        # Exercise the visitor's challenge with the keyboard, not a helper bypass.
        page.locator('#challenge').focus();page.keyboard.press('Enter')
        expect(page.locator('#answer')).to_be_enabled()
        expect(page.locator('#challenge')).to_be_disabled()
        self.assertRegex(page.locator('#challenge-value').inner_text(),r'^0x[0-9a-f]+$')
        page.locator('#answer').click()
        expect(page.locator('#proof-outcome')).to_be_visible(timeout=30000)
        self.assertNotIn('REJECT',page.locator('#equation-checks').inner_text())
        expect(page.locator('#answer')).to_be_disabled()
    def test_full_story_public_export_accessibility_and_state_reset(self):
        for width in (390,1360):
            with self.subTest(width=width):
                page=self.browser.new_page(viewport={'width':width,'height':900},reduced_motion='reduce')
                page.set_default_timeout(30000);errors=[]
                page.on('pageerror',lambda e:errors.append(str(e)))
                try:
                    page.goto(self.origin,wait_until='networkidle')
                    page.add_script_tag(path=str(ROOT/'research/real-pairing/node_modules/axe-core/axe.min.js'))
                    self.assertEqual(page.locator('h1').count(),1)
                    self.assertIn('These checks do not establish the security of the complete designated-confirmer signature scheme.',page.locator('#research-scope').text_content())
                    expect(page.locator('#chapter-1')).to_be_disabled()
                    self.access(page)
                    page.screenshot(path=str(ROOT/f'test-results/dcs-real-pairing-{width}-start.png'),full_page=True)
                    page.locator('#issue').click()
                    expect(page.locator('#proof-panel')).to_be_visible()
                    expect(page.locator('#begin-confirm')).to_be_enabled()
                    self.assertIn('Format and independent extraction',page.locator('#issue-status').text_content())
                    self.complete(page,'confirm')
                    page.locator('#role').select_option('signer')
                    self.complete(page,'confirm')
                    self.access(page)
                    page.screenshot(path=str(ROOT/f'test-results/dcs-real-pairing-{width}-confirmation.png'),full_page=True)
                    page.locator('#next-alter').click()
                    page.locator('input[name=alter-prediction][value=no]').check()
                    page.locator('#alter').click()
                    expect(page.locator('#begin-confirm')).to_be_enabled()
                    page.locator('#begin-confirm').click()
                    expect(page.locator('#proof-status')).to_contain_text('NOT proof of invalidity')
                    expect(page.locator('#challenge')).to_be_disabled()
                    self.complete(page,'deny')
                    page.locator('#role').select_option('confirmer')
                    self.complete(page,'deny')
                    page.locator('#next-eve').click()
                    page.locator('input[name=eve-prediction][value=reject]').check()
                    page.locator('#simulate').click()
                    expect(page.locator('#recording-verdict')).to_have_text('Recorded equations: PASS')
                    expect(page.locator('#challenge-eve')).to_be_enabled()
                    page.locator('#challenge-eve').click()
                    expect(page.locator('#live-verdict')).to_have_text('Live response: REJECT')
                    expect(page.locator('#takeaway')).to_be_visible()
                    self.assertNotEqual(page.locator('#eve-challenge').inner_text().split('0x')[1],page.locator('#live-challenge').inner_text().split('0x')[1])
                    self.access(page)
                    page.screenshot(path=str(ROOT/f'test-results/dcs-real-pairing-{width}-eve.png'),full_page=True)
                    self.assertEqual(page.locator('.participants .active').evaluate("e=>getComputedStyle(e).animationName"),'none')
                    page.locator('#open-evidence').click()
                    expect(page.locator('#research-panel')).to_be_visible()
                    with page.expect_download() as info:page.locator('#download').click()
                    filename=ROOT/f'test-results/public-transcript-{width}.json';info.value.save_as(filename)
                    data=json.loads(filename.read_text())
                    self.assertEqual(data['proof']['kind'],'disavowal')
                    for forbidden in ['privateKeys','_private','ePrime','secret']:
                        self.assertNotIn('"'+forbidden+'"',filename.read_text())
                    result=subprocess.run([sys.executable,str(ROOT/'research/real-pairing/reference/verify.py'),str(filename)],capture_output=True,text=True,timeout=60)
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                    self.access(page)
                    page.screenshot(path=str(ROOT/f'test-results/dcs-real-pairing-{width}-evidence.png'),full_page=True)
                    page.locator('#mode-explore').click()
                    expect(page.locator('#issue-panel')).to_be_visible()
                    expect(page.locator('#eve-panel')).to_be_visible()
                    self.assertTrue(page.locator('#equations').evaluate('e=>e.open'))
                    self.assertIn('z_pair = β^c',page.locator('#equations').inner_text())
                    # Editing the source statement must invalidate every old result/export.
                    page.locator('#message').fill('A fresh fictional agreement.')
                    expect(page.locator('#begin-confirm')).to_be_disabled()
                    expect(page.locator('#challenge-eve')).to_be_disabled()
                    self.assertIn('Not created',page.locator('#recording-verdict').inner_text())
                    page.locator('#mode-research').click();expect(page.locator('#download')).to_be_disabled()
                    page.locator('#mode-explore').click()
                    # The 600-character limit must not break Eve's alternate-message path.
                    if width==1360:
                        page.locator('#message').fill('a'*600);page.locator('#issue').click()
                        expect(page.locator('#begin-confirm')).to_be_enabled()
                        page.locator('#begin-confirm').click();expect(page.locator('#challenge')).to_be_enabled()
                        page.locator('#role').select_option('signer');expect(page.locator('#challenge')).to_be_disabled()
                        page.locator('input[name=eve-prediction][value=pass]').check();page.locator('#simulate').click()
                        expect(page.locator('#recording-verdict')).to_have_text('Recorded equations: PASS')
                    self.access(page)
                    page.locator('#reset').click();expect(page.locator('#begin-confirm')).to_be_disabled()
                    self.assertEqual(errors,[])
                finally:
                    page.screenshot(path=str(ROOT/f'test-results/dcs-real-pairing-{width}-final.png'),full_page=True)
                    page.close()
    def test_designated_verifier_chapter_both_origins_observer_and_public_contrast(self):
        """A-D-09: one verifier accepts a proof from Alice AND one the visitor forged."""
        for width in (390,1360):
            with self.subTest(width=width):
                page=self.browser.new_page(viewport={'width':width,'height':900},reduced_motion='reduce')
                page.set_default_timeout(30000);errors=[]
                page.on('pageerror',lambda e:errors.append(str(e)))
                try:
                    page.goto(self.origin,wait_until='networkidle')
                    page.add_script_tag(path=str(ROOT/'research/real-pairing/node_modules/axe-core/axe.min.js'))
                    expect(page.locator('#chapter-4')).to_be_disabled()
                    page.locator('#issue').click()
                    expect(page.locator('#chapter-4')).to_be_enabled()
                    page.locator('#chapter-4').click()
                    expect(page.locator('#dv-panel')).to_be_visible()
                    # Nothing can be proved before a verifier key exists to designate to.
                    expect(page.locator('#dv-prove')).to_be_disabled()
                    expect(page.locator('#dv-simulate')).to_be_disabled()
                    page.locator('#dv-key').focus();page.keyboard.press('Enter')
                    expect(page.locator('#dv-prove')).to_be_enabled(timeout=30000)
                    self.assertIn('registration check',page.locator('#dv-key-status').text_content())
                    self.access(page)

                    # Origin 1: the branch witness.
                    page.locator('#dv-prove').click()
                    expect(page.locator('#dv-witness-verdict')).to_have_text('Your verifier: ACCEPTED',timeout=60000)
                    witness_values=page.locator('#dv-math').text_content()
                    self.assertIn('USING THE BRANCH SECRET',witness_values)
                    # Origin 2: the visitor's own verifier secret, no branch secret at all.
                    page.locator('#dv-simulate').click()
                    expect(page.locator('#dv-verifier-verdict')).to_have_text('Your verifier: ACCEPTED',timeout=60000)
                    forged_values=page.locator('#dv-math').text_content()
                    self.assertIn('USING ONLY YOUR VERIFIER SECRET',forged_values)
                    self.assertNotEqual(witness_values,forged_values)
                    # The observer line must say the origin is undetermined.
                    self.assertIn('Possible origins',page.locator('#dv-observer-text').text_content())
                    self.access(page)
                    page.screenshot(path=str(ROOT/f'test-results/dcs-designated-verifier-{width}.png'),full_page=True)

                    # An accepting proof of a statement Alice never signed.
                    page.locator('#dv-false').click()
                    expect(page.locator('#dv-status')).to_contain_text('never signed',timeout=60000)
                    expect(page.locator('#dv-verifier-verdict')).to_have_text('Your verifier: ACCEPTED')

                    # The publicly verifiable contrast and honest-prover refusal.
                    page.locator('#dv-public').click()
                    expect(page.locator('#dv-status')).to_contain_text('public verifier',timeout=60000)
                    self.assertIn('PUBLICLY VERIFIABLE PROOF',page.locator('#dv-math').text_content())
                    page.locator('#dv-public-forge').click()
                    expect(page.locator('#dv-status')).to_contain_text('Refused',timeout=60000)
                    self.assertIn('not an unforgeability theorem',page.locator('#dv-observer-text').text_content())

                    # No secret may ever reach the rendered values.
                    shown=page.locator('#dv-math').text_content()
                    for forbidden in ('"secret"','"witness"','"alpha"','"beta"','privateKeys'):
                        self.assertNotIn(forbidden,shown)

                    # Changing the branch retires the chapter's results.
                    page.locator('#dv-role').select_option('signer')
                    expect(page.locator('#dv-witness-verdict')).to_have_text('Not created yet')
                    page.locator('#dv-prove').click()
                    expect(page.locator('#dv-witness-verdict')).to_have_text('Your verifier: ACCEPTED',timeout=60000)

                    # An altered claim: the honest prover refuses, the forgery still works.
                    page.locator('#mode-explore').click()
                    page.locator('#altered-message').fill('A different fictional agreement.')
                    page.locator('input[name=alter-prediction][value=no]').check()
                    page.locator('#alter').click()
                    page.locator('#dv-prove').click()
                    expect(page.locator('#dv-witness-verdict')).to_have_text('No proof was produced',timeout=60000)
                    page.locator('#dv-simulate').click()
                    expect(page.locator('#dv-verifier-verdict')).to_have_text('Your verifier: ACCEPTED',timeout=60000)

                    # Editing the signed statement retires every designated result.
                    page.locator('#message').fill('A fresh fictional agreement.')
                    expect(page.locator('#dv-prove')).to_be_disabled()
                    self.assertEqual(page.locator('#dv-witness-verdict').inner_text(),'Not created yet')
                    self.assertIn('No designated proof yet',page.locator('#dv-math').text_content())
                    self.access(page)
                    self.assertEqual(errors,[])
                finally:
                    page.close()

if __name__=='__main__':unittest.main()
