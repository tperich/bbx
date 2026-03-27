from bbx import core


def register(subparsers):
    p = subparsers.add_parser("export", help="Export a table/view")
    p.add_argument("program")
    p.add_argument("dataset")
    p.add_argument("--format", choices=["json", "csv"], default="json")
    p.add_argument("--tag")
    p.add_argument("--host")
    p.add_argument("--min-score", type=int)
    p.add_argument("--tool")
    p.add_argument("--contains")
    p.add_argument("--path-prefix")
    p.add_argument("--status")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--preset")
    p.set_defaults(func=core.cmd_export)
