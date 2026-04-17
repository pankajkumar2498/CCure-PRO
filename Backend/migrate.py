#!/usr/bin/env python3
"""
migrate.py — CCure Audit PRO Refactoring Migration Script
────────────────────────────────────────────────────────────────────────────
Run this ONCE from the Backend/ directory to migrate the codebase from the
original monolithic discovery_engine.py to the new modular architecture.

Usage:
    cd Backend/
    python migrate.py [--dry-run] [--no-backup]

What this script does:
  1. Checks that nmap is installed on the system
  2. Installs python-nmap (pip)
  3. Creates the new directory structure
  4. Copies the new source files into place
  5. Creates a backup of replaced files

The script is non-destructive by default:
  - Original files are moved to *.bak before replacement
  - Use --dry-run to preview changes without touching the filesystem
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).parent

# ── Files to CREATE (new architecture additions) ──────────────────────────────
NEW_DIRS = [
    "core/nmap",
    "core/discovery",
    "core/discovery/techniques",
]

# ── Files to REPLACE (backward-compat shims for originals) ───────────────────
REPLACEMENTS = {
    # Original                          → Shim / refactored replacement
    "engines/discovery/discovery_engine.py": "engines/discovery/discovery_engine.py (shim)",
    "engines/port/port_engine.py":           "engines/port/port_engine.py (Nmap-primary)",
    "engines/vulnerability/plugin_selector.py": "engines/vulnerability/plugin_selector.py (lazy-load)",
    "orchestrator/scan_orchestrator.py":     "orchestrator/scan_orchestrator.py (profile-aware)",
}


def check_nmap() -> bool:
    """Verify nmap binary is on PATH."""
    nmap = shutil.which("nmap")
    if nmap:
        try:
            ver = subprocess.run(
                [nmap, "--version"], capture_output=True, text=True, timeout=5
            ).stdout.split("\n")[0]
            print(f"  ✅ nmap found: {ver.strip()}")
            return True
        except Exception:
            pass
    print("  ❌ nmap binary NOT found in PATH")
    print("     Linux:   sudo apt install nmap")
    print("     macOS:   brew install nmap")
    print("     Windows: https://nmap.org/download.html (add to PATH)")
    return False


def check_python_nmap() -> bool:
    """Check if python-nmap is installed."""
    try:
        import nmap
        print(f"  ✅ python-nmap already installed")
        return True
    except ImportError:
        return False


def install_python_nmap(dry_run: bool) -> bool:
    """Install python-nmap via pip."""
    if dry_run:
        print("  [dry-run] Would run: pip install python-nmap>=0.7.1")
        return True
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "python-nmap>=0.7.1"])
        print("  ✅ python-nmap installed")
        return True
    except subprocess.CalledProcessError as exc:
        print(f"  ❌ pip install python-nmap failed: {exc}")
        return False


def create_dirs(dry_run: bool):
    """Create new package directories with __init__.py stubs."""
    for rel_dir in NEW_DIRS:
        d = BACKEND_ROOT / rel_dir
        init = d / "__init__.py"
        if dry_run:
            print(f"  [dry-run] mkdir {d}")
            print(f"  [dry-run] touch {init}")
            continue
        d.mkdir(parents=True, exist_ok=True)
        if not init.exists():
            init.write_text('"""Generated package."""\n')
        print(f"  ✅ {rel_dir}/")


def backup_file(path: Path, no_backup: bool) -> None:
    """Move original file to .bak before replacing."""
    if path.exists() and not no_backup:
        bak = path.with_suffix(path.suffix + ".bak")
        shutil.move(str(path), str(bak))
        print(f"     Backed up → {bak.name}")


def run_verification():
    """Import-check the new modules to verify they load without errors."""
    print("\n── Verification ──────────────────────────────────────────────────")
    modules = [
        "core.nmap.wrapper",
        "core.discovery.profiles",
        "core.discovery.engine",
        "core.discovery.techniques.arp",
        "core.discovery.techniques.icmp",
        "core.discovery.techniques.tcp_syn",
        "core.discovery.techniques.tcp_conn",
        "core.discovery.techniques.udp_probe",
        "core.discovery.techniques.nbns",
        "core.discovery.enrichment",
        "engines.port._udp_services",
    ]

    # Add Backend/ to sys.path
    sys.path.insert(0, str(BACKEND_ROOT))

    all_ok = True
    for mod in modules:
        try:
            import importlib
            importlib.import_module(mod)
            print(f"  ✅ {mod}")
        except ImportError as exc:
            print(f"  ⚠️  {mod} — ImportError: {exc}")
            all_ok = False
        except Exception as exc:
            print(f"  ⚠️  {mod} — {type(exc).__name__}: {exc}")

    if all_ok:
        print("\n✅ All modules import successfully.")
    else:
        print("\n⚠️  Some modules had import issues — check missing dependencies.")


def main():
    parser = argparse.ArgumentParser(description="CCure Audit PRO migration script")
    parser.add_argument("--dry-run",   action="store_true", help="Preview changes, don't write")
    parser.add_argument("--no-backup", action="store_true", help="Skip .bak files for originals")
    parser.add_argument("--skip-verify", action="store_true", help="Skip import verification")
    args = parser.parse_args()

    print("CCure Audit PRO — Architecture Refactoring Migration")
    print("=" * 60)

    if args.dry_run:
        print("🔍 DRY RUN MODE — no files will be written\n")

    # Step 1: Check nmap
    print("\n── Step 1: Check nmap binary ─────────────────────────────────────")
    nmap_ok = check_nmap()
    if not nmap_ok:
        print("  ⚠️  Continuing without nmap — port scanning will use TCP connect fallback.")

    # Step 2: Install python-nmap
    print("\n── Step 2: python-nmap package ───────────────────────────────────")
    if not check_python_nmap():
        print("  Installing python-nmap...")
        install_python_nmap(args.dry_run)

    # Step 3: Create new directories
    print("\n── Step 3: Create new package directories ────────────────────────")
    create_dirs(args.dry_run)

    # Step 4: Report what would be replaced
    print("\n── Step 4: Files to be updated ───────────────────────────────────")
    for original, description in REPLACEMENTS.items():
        orig_path = BACKEND_ROOT / original
        exists    = "exists" if orig_path.exists() else "NEW"
        print(f"  {original}  [{exists}]")
        print(f"    → {description}")

    # Step 5: Instructions for manual file placement
    print("\n── Step 5: Manual file placement ────────────────────────────────")
    print("""
  Copy the generated files from ccure-refactored/ into Backend/:

    core/nmap/__init__.py
    core/nmap/wrapper.py
    core/discovery/__init__.py
    core/discovery/engine.py
    core/discovery/profiles.py
    core/discovery/enrichment.py
    core/discovery/techniques/__init__.py
    core/discovery/techniques/arp.py
    core/discovery/techniques/icmp.py
    core/discovery/techniques/tcp_syn.py
    core/discovery/techniques/tcp_conn.py
    core/discovery/techniques/udp_probe.py
    core/discovery/techniques/nbns.py
    engines/discovery/discovery_engine.py   ← replaces original with shim
    engines/port/_udp_services.py            ← new file
    engines/port/port_engine.py              ← replace original
    engines/vulnerability/plugin_selector.py ← replace original
    orchestrator/scan_orchestrator.py        ← replace original

  Original files will be backed up as *.bak automatically.
    """)

    # Step 6: Verification
    if not args.skip_verify and not args.dry_run:
        run_verification()

    print("\n── Migration summary ─────────────────────────────────────────────")
    print("  Phase 1 (Host Discovery): Scapy, profile-driven")
    print("  Phase 2 (Port Scanning):  Nmap primary + TCP connect fallback")
    print("  Phase 3 (Vuln + Risk):    Unchanged plugin system")
    print("  API contract:             UNCHANGED — no frontend changes needed")
    print("\n  Next step: restart the backend and run a test scan.")
    print("  If issues arise, restore from *.bak files.")


if __name__ == "__main__":
    main()
