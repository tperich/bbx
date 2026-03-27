from bbx import core


def add_common_filters(p):
    p.add_argument("--preset")
    p.add_argument("--tag")
    p.add_argument("--host")
    p.add_argument("--min-score", type=int)
    p.add_argument("--tool")
    p.add_argument("--contains")
    p.add_argument("--path-prefix")
    p.add_argument("--status")
    p.add_argument("--format", choices=["text", "json", "csv"], default="text")


def register(subparsers):
    p = subparsers.add_parser("rank", help="Rank stored requests")
    p.add_argument("program")
    p.set_defaults(func=core.cmd_rank)

    p = subparsers.add_parser("top", help="Show top-ranked requests")
    p.add_argument("program")
    p.add_argument("--limit", type=int, default=10)
    add_common_filters(p)
    p.set_defaults(func=core.cmd_top)

    p = subparsers.add_parser("interesting-urls", help="Show interesting discovered URLs")
    p.add_argument("program")
    p.add_argument("--limit", type=int, default=25)
    add_common_filters(p)
    p.set_defaults(func=core.cmd_interesting_urls)

    p = subparsers.add_parser("summarize", help="Summarize stored data")
    p.add_argument("program")
    p.add_argument("--format", choices=["text", "json", "csv"], default="text")
    p.set_defaults(func=core.cmd_summarize)

    p = subparsers.add_parser("db-stats", help="Show database stats")
    p.add_argument("program")
    p.add_argument("--format", choices=["text", "json", "csv"], default="text")
    p.set_defaults(func=core.cmd_db_stats)

    p = subparsers.add_parser("graph", help="Export correlation graph")
    p.add_argument("program")
    p.add_argument("--format", choices=["mermaid", "dot", "json"], default="mermaid")
    p.add_argument("--tag")
    p.add_argument("--host")
    p.add_argument("--min-score", type=int)
    p.add_argument("--tool")
    p.add_argument("--contains")
    p.add_argument("--path-prefix")
    p.add_argument("--status")
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--out")
    p.add_argument("--preset")
    p.set_defaults(func=core.cmd_graph)
