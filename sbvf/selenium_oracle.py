"""Optional real-browser confirmation layer using Selenium WebDriver.

Needed because some XSS and all Clickjacking cases can only be confirmed by a real
browser executing scripts / rendering iframes (as argued in [4], which used JWebUnit).

This module is optional: if selenium is not installed the framework falls back to the
structural HTTP oracle. Import errors are swallowed so the rest of the framework runs
without a browser.
"""
from __future__ import annotations


class SeleniumChecker:
    def __init__(self, base_url: str, headless: bool = True):
        from selenium import webdriver  # imported lazily
        opts = webdriver.ChromeOptions()
        if headless:
            opts.add_argument("--headless=new")
        opts.add_argument("--no-sandbox")
        self.base = base_url.rstrip("/")
        self.driver = webdriver.Chrome(options=opts)
        self._alerts = 0

    def confirm_xss(self, path: str, param: str, payload: str) -> bool:
        """Load the endpoint with the payload and check whether a JS alert fires."""
        import urllib.parse
        from selenium.common.exceptions import NoAlertPresentException
        url = f"{self.base}{path}?{urllib.parse.urlencode({param: payload})}"
        self.driver.get(url)
        try:
            alert = self.driver.switch_to.alert
            alert.accept()
            return True
        except NoAlertPresentException:
            return False

    def confirm_framing(self, path: str) -> bool:
        """Load a page that embeds the target in an iframe and check it rendered."""
        html_doc = (
            f"<html><body><iframe id='t' src='{self.base}{path}'></iframe>"
            f"</body></html>")
        import base64
        data_url = "data:text/html;base64," + base64.b64encode(
            html_doc.encode()).decode()
        self.driver.get(data_url)
        try:
            iframe = self.driver.find_element("id", "t")
            self.driver.switch_to.frame(iframe)
            body = self.driver.find_element("tag name", "body")
            loaded = bool(body.text.strip())
            self.driver.switch_to.default_content()
            return loaded
        except Exception:
            return False

    def close(self):
        try:
            self.driver.quit()
        except Exception:
            pass
