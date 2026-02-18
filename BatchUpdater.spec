# -*- mode: python ; coding: utf-8 -*-
import os
from pathlib import Path


REQUIRED_DIR_MODELS = "models"
REQUIRED_DIR_CONFIG = "config"


def _warn_missing_required(path_name):
    print(
        f"WARNING: Required directory '{path_name}' is missing. "
        "Build may fail or runtime functionality may be incomplete."
    )


# Collect all model handler modules (exclude __init__.py)
model_files = []
if os.path.isdir(REQUIRED_DIR_MODELS):
    model_files = [
        f"models.{f.replace('.py', '')}"
        for f in os.listdir(REQUIRED_DIR_MODELS)
        if f.endswith("_handler.py")
    ]
    print(f"Discovered {len(model_files)} model handler module(s) from '{REQUIRED_DIR_MODELS}'.")
else:
    _warn_missing_required(REQUIRED_DIR_MODELS)

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

# Include config folder (required)
if os.path.isdir(REQUIRED_DIR_CONFIG):
    datas_list.append((REQUIRED_DIR_CONFIG, REQUIRED_DIR_CONFIG))
    print("Bundling 'config' folder (required runtime resources)")
else:
    _warn_missing_required(REQUIRED_DIR_CONFIG)

# Include models folder (required)
if os.path.isdir(REQUIRED_DIR_MODELS):
    datas_list.append((REQUIRED_DIR_MODELS, REQUIRED_DIR_MODELS))
    print("Bundling 'models' folder (required model handlers)")

# Include model-specific automation scripts (optional extension point)
if os.path.isdir("scripts"):
    datas_list.append(("scripts", "scripts"))
    print("Bundling 'scripts' folder for model specific steps")
else:
    print("INFO: No 'scripts' folder found, skip bundling optional scripts.")

# Include translation file for GUI texts
if os.path.exists("translations.json"):
    datas_list.append(("translations.json", "."))
    print("Bundling translations.json for i18n support")
else:
    print("WARNING: translations.json not found; UI i18n may not work in packaged build.")

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
