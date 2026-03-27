from bbx import core


def register(subparsers):
    p = subparsers.add_parser("init", help="Initialize a workspace at the given path")
    p.add_argument("program")
    p.set_defaults(func=core.cmd_init)

    p = subparsers.add_parser("doctor", help="Run workspace health checks")
    p.add_argument("program")
    p.add_argument("--format", choices=["text", "json", "csv"], default="text")
    p.set_defaults(func=core.cmd_doctor)
