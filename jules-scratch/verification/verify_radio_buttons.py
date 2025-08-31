from playwright.sync_api import sync_playwright, expect

def run(playwright):
    browser = playwright.chromium.launch(headless=True)
    context = browser.new_context()
    page = context.new_page()

    # Helper function to log in
    def login(username, password):
        page.goto("http://127.0.0.1:8000/login")
        page.locator('input[name="username"]').fill(username)
        page.locator('input[name="password"]').fill(password)
        page.get_by_role("button", name="Sign in").click()
        page.wait_for_url("http://127.0.0.1:8000/")

    # 1. Log in as admin
    login("admin", "admin123")

    # 2. Navigate to the Manage Clients page
    page.goto("http://127.0.0.1:8000/admin/clients")

    # 3. Verify that the radio buttons are present
    expect(page.get_by_label("All", exact=True)).to_be_visible()
    expect(page.get_by_label("Not Churned", exact=True)).to_be_visible()
    expect(page.get_by_label("Churned", exact=True)).to_be_visible()

    # 4. Click the "Churned" radio button and verify the filter
    page.get_by_label("Churned", exact=True).check()
    page.wait_for_url("http://127.0.0.1:8000/admin/clients?filter=churned")
    expect(page.get_by_label("Churned", exact=True)).to_be_checked()

    # 5. Take a screenshot
    page.screenshot(path="jules-scratch/verification/verification.png")

    browser.close()

with sync_playwright() as playwright:
    run(playwright)
