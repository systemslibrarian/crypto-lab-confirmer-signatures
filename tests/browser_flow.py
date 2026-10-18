"""Executed on GitHub Actions with Playwright Chromium against locally served static files.
Real interaction assertions (not mocked browser crypto); this is NOT a DCS test.
"""
import http.server
import socketserver
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

class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

class BrowserFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = Server(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f'http://127.0.0.1:{cls.server.server_address[1]}/prototype/'
        cls.pw = sync_playwright().start()
        cls.browser = cls.pw.chromium.launch()
        (ROOT / 'test-results').mkdir(exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()
        cls.server.shutdown()

    def test_actual_public_signature_flow_mobile_and_desktop(self):
        for width in (390, 1350):
            with self.subTest(width=width):
                page = self.browser.new_page(viewport={'width': width, 'height': 950}, reduced_motion='reduce')
                errors = []
                page.on('pageerror', lambda exc: errors.append(str(exc)))
                try:
                    page.goto(self.origin, wait_until='networkidle')
                    self.assertEqual(page.locator('h1').count(), 1)
                    self.assertTrue(page.locator('#generate').is_enabled())
                    self.assertTrue(page.locator('#sign').is_disabled())
                    self.assertTrue(page.get_by_text('The separate protocol where Carol proves a signature valid or invalid is not yet implemented', exact=False).count() >= 1)
                    self.assertIn('Alice signs a private agreement.', page.locator('.cl-hero-why').inner_text())
                    self.assertIn('Carol helps Bob check', page.locator('.chapter-nav').inner_text())
                    self.assertEqual(page.locator('.chapter-nav .locked').count(), 4)
                    page.locator('#generate').click()
                    page.get_by_text('KEYS GENERATED').wait_for()
                    self.assertEqual(len(page.locator('#fingerprint').inner_text()), 64)
                    page.locator('#sign').click()
                    page.get_by_text('SIGNED — PUBLICLY VERIFIABLE').wait_for()
                    self.assertEqual(len(page.locator('#signature').inner_text()), 128)
                    page.locator('#verify-bob').click()
                    page.locator('#bob-result[data-verdict="pass"]').wait_for()
                    page.locator('#verify-dave').click()
                    page.locator('#dave-result[data-verdict="pass"]').wait_for()
                    page.locator('#tamper').click()
                    self.assertEqual(page.locator('#bob-result').inner_text(), 'NOT TESTED')
                    page.locator('#verify-bob').click()
                    page.locator('#bob-result[data-verdict="reject"]').wait_for()
                    page.locator('#verify-dave').click()
                    page.locator('#dave-result[data-verdict="reject"]').wait_for()
                    page.locator('#reset').click()
                    self.assertTrue(page.locator('#verify-bob').is_disabled())
                    self.assertEqual(page.locator('#signature').inner_text(), 'Not signed')
                    self.assertTrue(page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1'))
                    self.assertEqual(errors, [])
                    page.screenshot(path=str(ROOT / f'test-results/signature-gate-{width}.png'), full_page=True)
                finally:
                    page.close()

    def test_edit_retires_a_previous_verified_verdict(self):
        page = self.browser.new_page()
        try:
            page.goto(self.origin)
            page.locator('#generate').click()
            page.get_by_text('KEYS GENERATED').wait_for()
            page.locator('#sign').click()
            page.locator('#verify-bob').click()
            page.locator('#bob-result[data-verdict="pass"]').wait_for()
            page.locator('#statement').fill('Package withheld.')
            self.assertEqual(page.locator('#bob-result').inner_text(), 'NOT TESTED')
            page.locator('#verify-bob').click()
            page.locator('#bob-result[data-verdict="reject"]').wait_for()
        finally:
            page.close()


    def test_source_symbolic_or_confirmation_both_roles_and_missing_disavowal(self):
        for width in (390, 1270):
            with self.subTest(width=width):
                page = self.browser.new_page(viewport={'width': width, 'height': 900}, reduced_motion='reduce')
                errors=[]
                page.on('pageerror', lambda err: errors.append(str(err)))
                try:
                    page.goto(self.origin+'symbolic/', wait_until='networkidle')
                    self.assertEqual(page.locator('h1').count(),1)
                    self.assertIn('NOT SECURE CRYPTOGRAPHY', page.locator('#scope').inner_text())
                    self.assertIn('does not implement disavowal', page.locator('#disavow').inner_text())
                    self.assertTrue(page.locator('#issue').is_disabled())
                    page.locator('#keys').click()
                    page.get_by_text('Toy keys generated',exact=False).wait_for()
                    page.locator('#issue').click()
                    page.get_by_text('Source-structured symbolic signature issued',exact=False).wait_for()
                    self.assertIn('Format proof: PASS',page.locator('#issue-data').inner_text())
                    self.assertIn('Confirmer extraction check: PASS',page.locator('#issue-data').inner_text())
                    page.locator('#carol').click()
                    page.wait_for_function("document.querySelector('#proof-data').textContent.includes('groupPairing1: MATCH')")
                    self.assertIn('equations',page.locator('#verdict').inner_text())
                    self.assertIn('groupKey2: MATCH',page.locator('#proof-data').inner_text())
                    page.locator('#alice').click()
                    page.wait_for_function("document.querySelector('#proof-data').textContent.includes('Alice (signer)')")
                    self.assertIn('groupKey1: MATCH',page.locator('#proof-data').inner_text())
                    page.locator('#change').click()
                    page.wait_for_function("document.querySelector('#verdict').textContent.includes('NOT a mathematical disavowal')")
                    page.locator('#message').fill('Different fictional agreement')
                    self.assertTrue(page.locator('#carol').is_disabled())
                    self.assertTrue(page.evaluate('document.documentElement.scrollWidth<=innerWidth+1'))
                    self.assertEqual(errors,[])
                    page.screenshot(path=str(ROOT / f'test-results/signature-gate-symbolic-{width}.png'),full_page=True)
                finally:
                    page.close()

if __name__ == '__main__':
    unittest.main()
