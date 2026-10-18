"""Real BLS12-381 experiment: actual browser execution, not mocked cryptography."""
import http.server
import threading
import unittest
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)
    def log_message(self, *args):
        pass

class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

class RealPairingBrowser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert (ROOT / 'dist/real/index.html').is_file(), 'Run npm run build in research/real-pairing first'
        cls.server = Server(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f'http://127.0.0.1:{cls.server.server_address[1]}/dist/real/'
        cls.pw = sync_playwright().start()
        cls.browser = cls.pw.chromium.launch()
        (ROOT / 'test-results').mkdir(exist_ok=True)
    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()
        cls.server.shutdown()

    def test_real_issued_signature_confirmation_candidate_disavowal_and_simulator(self):
        for width in (390, 1360):
            with self.subTest(width=width):
                page=self.browser.new_page(
                    viewport={'width':width,'height':900},
                    reduced_motion='reduce'
                )
                page.set_default_timeout(25000)
                errors=[]
                page.on('pageerror',lambda e: errors.append(str(e)))
                try:
                    page.goto(self.origin,wait_until='networkidle')
                    self.assertEqual(page.locator('h1').count(),1)
                    self.assertIn('NOT A FINISHED OR SECURITY-PROVEN DCS',
                                  page.locator('#research-scope').inner_text())
                    self.assertTrue(page.locator('#issue').is_enabled())
                    page.locator('#issue').click()
                    page.wait_for_function(
                        "document.querySelector('#issue-status').textContent.includes('Signed-ElGamal format and confirmer extraction both passed')")
                    page.locator('details:has(#issue-math) summary').click()
                    self.assertIn('PASS',page.locator('#issue-math').inner_text())
                    page.locator('#confirm-carol').click()
                    page.wait_for_function(
                        "document.querySelector('#confirm-status').textContent.includes('five real pairing/point equations matched')")
                    page.locator('details:has(#confirm-math) summary').click()
                    self.assertIn('MATCH',page.locator('#confirm-math').inner_text())
                    page.locator('#confirm-alice').click()
                    page.wait_for_function(
                        "document.querySelector('#confirm-status').textContent.includes('Alice answered')")
                    page.locator('#simulate').click()
                    page.wait_for_function(
                        "document.querySelector('#simulate-status').textContent.includes('Eve’s computed transcript PASSED')")
                    page.locator('details:has(#simulate-math) summary').click()
                    self.assertIn('SIMULATED CONFIRMATION',page.locator('#simulate-math').inner_text())
                    page.locator('#alter').click()
                    self.assertIn('altered',page.locator('#deny-status').inner_text())
                    page.locator('#confirm-carol').click()
                    page.wait_for_function(
                        "document.querySelector('#confirm-status').textContent.includes('cannot honestly confirm')")
                    page.locator('#deny-carol').click()
                    page.wait_for_function(
                        "document.querySelector('#deny-status').textContent.includes('candidate inequality relation')")
                    page.locator('details:has(#deny-math) summary').click()
                    self.assertIn('MATCH',page.locator('#deny-math').inner_text())
                    page.locator('#deny-alice').click()
                    page.wait_for_function(
                        "document.querySelector('#deny-status').textContent.includes('Alice proved')")
                    self.assertTrue(page.evaluate(
                        'document.documentElement.scrollWidth <= innerWidth + 1'))
                    self.assertFalse(errors,errors)
                    page.screenshot(
                        path=str(ROOT / f'test-results/dcs-real-pairing-{width}.png'),
                        full_page=True
                    )
                    page.locator('#reset').click()
                    self.assertIn('Issue a new',page.locator('#issue-status').inner_text())
                    self.assertTrue(page.locator('#confirm-carol').is_disabled())
                finally:
                    page.close()

if __name__=='__main__':
    unittest.main()
