# -*- mode: python ; coding: utf-8 -*-
import os
from pathlib import Path

# Collect all model handler modules (exclude __init__.py)
model_files = [
    f"models.{f.replace('.py', '')}"
    for f in os.listdir("models")
    if f.endswith("_handler.py")
]

# Locate Playwright browser folder (Chromium)
playwright_browsers_path = Path.home() / "AppData" / "Local" / "ms-playwright"

# Find installed Chromium version (if any)
chromium_dirs = list(playwright_browsers_path.glob("chromium-*"))
if not chromium_dirs:
    print("WARNING: Playwright Chromium browser not found. Run: playwright install chromium")
    chromium_path = None
else:
    chromium_path = sorted(chromium_dirs)[-1]
    print(f"Found Chromium browser at: {chromium_path}")

# Build datas list (extra files to bundle)
datas_list = []

# Include config folder (CIDR-BOX scripts etc.)
datas_list.append(("config", "config"))
print("Bundling 'config' folder (CIDR-BOX scripts etc.)")

# Include model-specific automation scripts
datas_list.append(("scripts", "scripts"))
print("Bundling 'scripts' folder for model specific steps")

# Include translation file for GUI texts
datas_list.append(("translations.json", "."))
print("Bundling translations.json for i18n support")

if chromium_path and chromium_path.exists():
    # Bundle the whole Chromium folder so Playwright can find it
    datas_list.append(
        (str(chromium_path), f"playwright/driver/package/.local-browsers/{chromium_path.name}")
    )
    print(f"Bundling Chromium browser files from: {chromium_path}")

a = Analysis(
    ["main_app.py"],
    pathex=[],
    binaries=[],
    datas=datas_list,
    hiddenimports=model_files + ["playwright", "playwright.sync_api", "playwright._impl._api_types"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="BatchUpdater-1.0.7",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version="version.txt",
    uac_admin=True
)
