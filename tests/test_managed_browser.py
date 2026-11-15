"""Real web vault, real Rust keys, fictional account authority, isolated data."""

import html
import os
import threading
import pytest
from test_provider_login_routes import PASSWORD

pytest_plugins = ["test_managed_vault_routes"]


@pytest.mark.skipif(
    not os.environ.get("KAGNODE_MANAGED_BROWSER"),
    reason="Explicit browser qualification is required",
)
def test_browser_explicit_link_consent_then_password_free_signin(managed):
    from test_managed_vault_routes import make_local
    from playwright.sync_api import sync_playwright, expect
    from werkzeug.serving import make_server

    app, client, fake, _ = managed
    make_local(client)
    server = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = "http://127.0.0.1:" + str(server.server_port)
    engine = os.environ.get("KAGNODE_BROWSER_ENGINE", "chromium")
    try:
        with sync_playwright() as playwright:
            options = {"headless": True}
            if os.environ.get("KAGNODE_BROWSER_EXECUTABLE"):
                options["executable_path"] = os.environ["KAGNODE_BROWSER_EXECUTABLE"]
            browser = getattr(playwright, engine).launch(**options)
            for width in [390, 1440]:
                context = browser.new_context(viewport={"width": width, "height": 900})
                page = context.new_page()
                errors = []
                unlock_posts = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.on(
                    "request",
                    lambda request: unlock_posts.append(request.url)
                    if request.method == "POST" and request.url.endswith("/api/unlock")
                    else None,
                )

                def authorize(route):
                    callback = html.escape(
                        origin + "/auth/kagnode/callback", quote=True
                    )
                    state = html.escape(fake.device["state"], quote=True)
                    route.fulfill(
                        content_type="text/html",
                        body=f'<form action="{callback}"><input type="hidden" name="state" value="{state}"><input type="hidden" name="iss" value="https://nebulacoder.com"><button name="code" value="'
                        + "C" * 43
                        + '">Approve</button></form>',
                    )

                context.route("https://nebulacoder.com/oauth/authorize?**", authorize)
                page.goto(origin + "/unlock")
                provider = page.locator("[data-core-login-provider]")
                expect(provider).to_be_enabled()
                provider.click()
                page.get_by_role("button", name="Approve", exact=True).click()
                if width == 390:
                    page.get_by_role(
                        "button", name="Link existing account", exact=True
                    ).click()
                    page.locator("#auth-email").fill("local@example.test")
                    page.locator("#auth-form").get_by_role(
                        "button", name="Continue", exact=True
                    ).click()
                    page.locator("#master-password").fill(PASSWORD)
                    page.locator("#provider-managed-consent").check()
                    page.locator("#auth-form button[type=submit]").click()
                expect(page.locator("#dashboard")).to_be_visible(timeout=20000)
                page.locator("[data-core-account-trigger]").click()
                page.locator("[data-core-account-menu] button").last.click()
                expect(provider).to_be_enabled()
                provider.click()
                page.get_by_role("button", name="Approve", exact=True).click()
                expect(page.locator("#dashboard")).to_be_visible(timeout=20000)
                assert len(unlock_posts) == (1 if width == 390 else 0)
                assert not errors, errors
                assert "code=" not in page.url and "state=" not in page.url
                assert page.evaluate(
                    "document.documentElement.scrollWidth <= innerWidth + 1"
                ), page.evaluate(
                    "[...document.querySelectorAll('body *')].filter(e=>e.getBoundingClientRect().right>innerWidth+1&&getComputedStyle(e).visibility!=='hidden').slice(0,20).map(e=>({tag:e.tagName,id:e.id,cls:e.className,width:e.getBoundingClientRect().width,right:e.getBoundingClientRect().right,margin:getComputedStyle(e).marginLeft,box:getComputedStyle(e).boxSizing,root:document.documentElement.outerHTML.slice(0,1000)}))"
                )
                context.close()
            browser.close()
    finally:
        server.shutdown()
