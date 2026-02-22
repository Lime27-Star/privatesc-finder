#!/usr/bin/env python3
"""
main.py — Privilege Escalation Path Finder
Usage:
  python3 main.py                    # auto-detect OS, run all modules
  python3 main.py --linux            # force Linux modules
  python3 main.py --windows          # force Windows modules
  python3 main.py --module suid      # run a single module
  python3 main.py --verbose          # show all findings inline
  python3 main.py --no-html          # skip HTML report generation
  python3 main.py --out /tmp/results # custom output directory
"""

import sys
import os
import argparse

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.platform import get_system_context, print_context_banner
from core.scanner import Scanner
from core.reporter import generate_html, generate_json

BANNER = r"""
  ____       _       _____              _____ _           _
 |  _ \ _ __(_)_   _| ____|___  ___   |  ___(_)_ __   __| | ___ _ __
 | |_) | '__| \ \ / /  _| / __|/ __|  | |_  | | '_ \ / _` |/ _ \ '__|
 |  __/| |  | |\ V /| |___\__ \ (__   |  _| | | | | | (_| |  __/ |
 |_|   |_|  |_| \_/ |_____|___/\___|  |_|   |_|_| |_|\__,_|\___|_|

 Privilege Escalation Path Finder  •  Use only on systems you own
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="Privilege Escalation Path Finder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--linux",    action="store_true", help="Force Linux scan modules")
    parser.add_argument("--windows",  action="store_true", help="Force Windows scan modules")
    parser.add_argument("--module",   type=str, help="Run single module (suid|sudo|kernel|perms|caps|services)")
    parser.add_argument("--verbose",  action="store_true", help="Print each finding inline during scan")
    parser.add_argument("--no-html",  action="store_true", help="Skip HTML report generation")
    parser.add_argument("--out",      type=str, default="output", help="Output directory (default: ./output)")
    parser.add_argument("--data",     type=str, default="data",   help="Data directory (default: ./data)")
    return parser.parse_args()


def run_single_module(name: str, data_dir: str) -> None:
    """Run and print results for a single named module."""
    module_map = {
        "suid":     ("modules.linux.suid",         "SuidModule"),
        "sudo":     ("modules.linux.sudo",         "SudoModule"),
        "kernel":   ("modules.linux.kernel",       "KernelModule"),
        "perms":    ("modules.linux.permissions",  "PermissionsModule"),
        "caps":     ("modules.linux.capabilities", "CapabilitiesModule"),
        "services": ("modules.linux.services",     "ServicesModule"),
    }
    if name not in module_map:
        print(f"[!] Unknown module '{name}'. Choices: {', '.join(module_map)}")
        sys.exit(1)

    mod_path, cls_name = module_map[name]
    import importlib
    mod = importlib.import_module(mod_path)
    cls = getattr(mod, cls_name)
    instance = cls(data_dir)

    print(f"\n[*] Running module: {cls_name}")
    print("-" * 50)
    findings = instance.run()
    if not findings:
        print("  No findings.")
        return
    for f in findings:
        print(f.pretty())
        print()
    print(f"\n  {len(findings)} finding(s) from module '{name}'")


def main():
    print(BANNER)

    args = parse_args()
    ctx = get_system_context()
    print_context_banner(ctx)

    # Single-module mode
    if args.module:
        run_single_module(args.module.lower(), args.data)
        return

    # Determine platform
    if args.linux:
        platform = "linux"
    elif args.windows:
        platform = "windows"
    else:
        platform = ctx.os_type

    print(f"[*] Scanning platform: {platform.upper()}")
    print()

    scanner = Scanner(data_dir=args.data, verbose=args.verbose)

    if platform == "linux":
        scanner.run_linux()
    elif platform in ("windows", "win32"):
        scanner.run_windows()
    else:
        print(f"[!] Platform '{platform}' not yet supported. Use --linux or --windows.")
        sys.exit(1)

    # Build attack paths
    print("\n[*] Building attack paths...")
    scanner.build_attack_paths()

    # Print terminal summary
    scanner.print_summary()

    # Generate reports
    print("\n[*] Generating reports...")
    os.makedirs(args.out, exist_ok=True)

    generate_json(
        scanner.findings,
        scanner.attack_paths,
        ctx,
        output_path=os.path.join(args.out, "attack_paths.json"),
    )

    if not args.no_html:
        generate_html(
            scanner.findings,
            scanner.attack_paths,
            ctx,
            output_path=os.path.join(args.out, "report.html"),
            template_path="templates/report.html.j2",
        )

    print("\n[+] Done.")


if __name__ == "__main__":
    main()
