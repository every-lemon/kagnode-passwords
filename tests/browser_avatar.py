"""Avatar relocation/absence cannot interrupt real disposable vault transitions."""

import json
import os
from pathlib import Path
import sys
import tempfile
import threading

from playwright.sync_api import expect, sync_playwright
from werkzeug.serving import make_server

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from authentactor.server import create_app
from authentactor import kagnode_core

PASSWORD = "Disposable avatar test password!2048"
expect.set_options(timeout=15000)


def sign_in(page, email):
    page.locator("#auth-email").fill(email)
    if not page.locator("#master-password").is_visible():
        page.locator("#auth-form").get_by_role(
            "button", name="Continue", exact=True
        ).click()
    page.locator("#master-password").fill(PASSWORD)
    page.locator("#auth-form").get_by_role("button", name="Sign in", exact=True).click()
    expect(page.locator("#dashboard")).to_be_visible()
    expect(page.locator("#account-email")).to_have_text(email)


def check(browser, origin, placement):
    context = browser.new_context(viewport={"width": 1440, "height": 900})
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    first_status = True

    def status(route):
        nonlocal first_status
        if first_status:
            first_status = False
            # Reproduce Core's reparenting before the initial session response,
            # including when CI is using the older bundled fallback Core.
            page.evaluate(
                """placement => {
                  const avatar=document.querySelector('[data-kn-account-avatar]');
                  window.avatarFixture=avatar;
                  let footer=document.querySelector('.kn-core-sidebar-footer');
                  if(!footer) {
                    footer=document.createElement('footer');
                    footer.className='kn-core-sidebar-footer';
                    document.querySelector('#sidebar').append(footer);
                  }
                  const owned=document.createElement('span');
                  owned.dataset.avatarTestOwned='';owned.textContent='Core-owned child';
                  avatar.append(owned);
                  if(placement==='missing') avatar.remove(); else footer.prepend(avatar);
                }""",
                placement,
            )
        route.continue_()

    page.route("**/api/status", status)
    baseline = os.environ.get("KAGNODE_TEST_BASELINE_APP")
    if baseline:
        page.route(
            "**/static/built/app.*.js",
            lambda route: route.fulfill(
                content_type="text/javascript", body=Path(baseline).read_text()
            ),
        )
    page.goto(origin + "/unlock")
    expect(page.locator("#auth-screen")).to_be_visible()
    assert not errors, errors
    sign_in(page, "alice@avatar.test")
    assert not errors, errors
    if placement == "missing":
        page.evaluate(
            """() => {
              document.querySelector('.kn-core-sidebar-footer').prepend(window.avatarFixture);
              document.dispatchEvent(new Event('kagnode:core-ready'));
            }"""
        )
    avatar = page.locator("[data-kn-account-avatar]")
    expect(avatar.locator("[data-vault-avatar-initials]")).to_have_text("A")
    expect(avatar.locator("[data-avatar-test-owned]")).to_have_count(1)
    expect(avatar).to_have_attribute("aria-label", "Open account menu")
    assert avatar.evaluate("e=>!e.closest('.topbar')")
    # A previously linked image and cached initials must not survive lock/switch.
    page.evaluate(
        """() => {
          const avatar=document.querySelector('[data-kn-account-avatar]');
          const photo=document.createElement('img');photo.className='kn-linked-avatar';
          avatar.append(photo);avatar.classList.add('kn-has-linked-photo');
          document.querySelector('#item-password').value='synthetic cleared secret';
        }"""
    )
    avatar.click()
    page.locator("#kn-core-account-menu").get_by_role(
        "button", name="Sign out", exact=True
    ).evaluate("button=>button.click()")
    expect(page.locator("#auth-screen")).to_be_visible()
    expect(avatar.locator("[data-vault-avatar-initials]")).to_have_text("?")
    expect(avatar.locator(".kn-linked-avatar")).to_have_count(0)
    expect(page.locator("#item-password")).to_have_value("")
    expect(page.locator("#items")).to_be_empty()
    expect(page.locator("#account-email")).to_be_empty()
    assert avatar.get_attribute("data-kn-local-initials") == "?"
    assert not avatar.evaluate("e=>e.classList.contains('kn-has-linked-photo')")
    expect(avatar.locator("[data-avatar-test-owned]")).to_have_count(1)
    sign_in(page, "bob@avatar.test")
    expect(avatar.locator("[data-vault-avatar-initials]")).to_have_text("B")
    expect(avatar).to_have_attribute("title", "bob@avatar.test")
    avatar.click()
    expect(page.locator(".kn-core-account-identity")).to_contain_text("bob@avatar.test")
    assert (
        "alice@avatar.test"
        not in page.locator(".kn-core-account-identity").inner_text()
    )
    assert not errors, errors
    context.close()


def main():
    # Optional newer Core bundle is read only into this disposable process.
    bundle = os.environ.get("KAGNODE_TEST_CORE_BUNDLE")
    if bundle:
        kagnode_core.BUNDLE = json.loads(Path(bundle).read_text())
    with tempfile.TemporaryDirectory(prefix="passwords-avatar-") as scratch:
        app = create_app(Path(scratch) / "vault", preview=True)
        app.config["TESTING"] = True
        for email in ["alice@avatar.test", "bob@avatar.test"]:
            with app.test_client() as client:
                response = client.post(
                    "/api/setup",
                    json={"email": email, "password": PASSWORD},
                    headers={"X-Requested-With": "Authentactor"},
                )
                assert response.status_code == 200
        server = make_server("127.0.0.1", 0, app, threaded=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with sync_playwright() as playwright:
                engine = os.environ.get("KAGNODE_BROWSER_ENGINE", "chromium")
                executable = os.environ.get("KAGNODE_BROWSER_EXECUTABLE")
                browser = getattr(playwright, engine).launch(
                    headless=True,
                    **({"executable_path": executable} if executable else {}),
                )
                try:
                    for placement in ["footer", "missing"]:
                        check(
                            browser, f"http://127.0.0.1:{server.server_port}", placement
                        )
                        print(
                            f"PASS: {engine}, {placement}, lock/unlock/account switch"
                        )
                finally:
                    browser.close()
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()


if __name__ == "__main__":
    main()
