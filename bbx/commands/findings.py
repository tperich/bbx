from bbx import core


def register(subparsers):
    p = subparsers.add_parser("new-finding", help="Create a new finding template")
    p.add_argument("program")
    p.add_argument("slug")
    p.add_argument("--title")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=core.cmd_new_finding)

    p = subparsers.add_parser("set-finding-status", help="Set finding status")
    p.add_argument("program")
    p.add_argument("slug")
    p.add_argument("status")
    p.set_defaults(func=core.cmd_set_finding_status)

    p = subparsers.add_parser("list-findings", help="List findings")
    p.add_argument("program")
    p.add_argument("--format", choices=["text", "json", "csv"], default="text")
    p.add_argument("--status")
    p.set_defaults(func=core.cmd_list_findings)
