from bbx import core

def register(subparsers):
    p = subparsers.add_parser("preset-save", help="Save a filter preset")
    p.add_argument("program")
    p.add_argument("name")
    p.add_argument("--tag")
    p.add_argument("--host")
    p.add_argument("--min-score", type=int)
    p.add_argument("--tool")
    p.add_argument("--contains")
    p.add_argument("--path-prefix")
    p.add_argument("--status")
    p.set_defaults(func=core.cmd_preset_save)

    p = subparsers.add_parser("preset-list", help="List presets")
    p.add_argument("program")
    p.set_defaults(func=core.cmd_preset_list)

    p = subparsers.add_parser("preset-show", help="Show a preset")
    p.add_argument("program")
    p.add_argument("name")
    p.set_defaults(func=core.cmd_preset_show)

    p = subparsers.add_parser("preset-delete", help="Delete a preset")
    p.add_argument("program")
    p.add_argument("name")
    p.set_defaults(func=core.cmd_preset_delete)
