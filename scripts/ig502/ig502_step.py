#!/usr/bin/env python3
"""IG502 pre-config automation script.

Based on the provided Playwright sequence. It supports runtime arguments from the app,
and prints progress logs to stdout for UI display.
"""

import argparse
import os
import sys
from playwright.sync_api import sync_playwright


def click_select_file_and_upload(page, file_path: str):
    if not file_path or not os.path.exists(file_path):
        print(f"[WARN] File not found, skip upload: {file_path}")
        return
    page.locator("button").filter(has_text="Select File").first.click()
    page.locator("button").filter(has_text="Select File").first.set_input_files(file_path)
    page.get_by_role("button", name="Confirm").click()


def run(ip, username, password, protocol, firmware, edge_config, import_config):
    base_url = f"{protocol}://{ip}"
    print(f"[INFO] Open: {base_url}/user/login")

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        page.goto(f"{base_url}/user/login")
        page.get_by_role("textbox", name="Username").click()
        page.get_by_role("textbox", name="Username").fill(username)
        page.get_by_role("textbox", name="Password").click()
        page.get_by_role("textbox", name="Password").fill(password)
        page.get_by_role("textbox", name="Password").press("Enter")

        # Script flow from provided image
        page.get_by_role("link", name="icon: cloud-server Edge").click()
        page.get_by_role("button", name="icon: plus-circle").click()
        click_select_file_and_upload(page, firmware)

        page.goto(f"{base_url}/edge-computing/python")
        page.get_by_role("button", name="icon: upload", exact=True).click()
        click_select_file_and_upload(page, edge_config)

        page.get_by_label("", exact=True).check()
        page.get_by_role("button", name="Submit").click()

        page.get_by_role("link", name="Device Supervisor").click()
        page.get_by_role("link", name="Python Edge Computing").click()
        page.get_by_text("Device Supervisor").click()
        page.get_by_role("link", name="Measure Monitor").click()
        page.get_by_text("Measuring Point list(CWT-8-8)").dblclick()
        page.get_by_text("Measuring Point list(CWT-8-8)").dblclick()
        page.get_by_role("link", name="icon: setting System").click()
        page.get_by_role("link", name="Configuration Management").click()

        click_select_file_and_upload(page, import_config)
        page.get_by_role("button", name="Import Config").click()
        page.get_by_role("button", name="Reboot").click()

        print("[INFO] IG502 script flow completed")
        context.close()
        browser.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--protocol", default="http")
    parser.add_argument("--firmware", default="")
    parser.add_argument("--edge-config", default="")
    parser.add_argument("--import-config", default="")
    parser.add_argument("--expected-ip", default="192.168.1.1")
    args = parser.parse_args()

    try:
        run(
            ip=args.ip,
            username=args.username,
            password=args.password,
            protocol=args.protocol,
            firmware=args.firmware,
            edge_config=args.edge_config,
            import_config=args.import_config,
        )
        # Success criteria is validated by caller (app side IP switch check).
        print(f"[INFO] Waiting for target IP switch to {args.expected_ip} (validated by app)")
        return 0
    except Exception as exc:
        print(f"[ERROR] IG502 script failed: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
