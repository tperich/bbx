from __future__ import annotations

import argparse

from bbx.commands import analysis, exports, findings, imports, presets, scan, tags, workspace


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bbx", description="Bug bounty toolkit")
    subparsers = parser.add_subparsers(dest="command")

    workspace.register(subparsers)
    imports.register(subparsers)
    analysis.register(subparsers)
    findings.register(subparsers)
    tags.register(subparsers)
    exports.register(subparsers)
    presets.register(subparsers)
    scan.register(subparsers)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    return int(args.func(args) or 0)
