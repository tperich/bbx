from bbx import core


def register(subparsers):
    p = subparsers.add_parser("tag-add", help="Add a tag to an item")
    p.add_argument("program")
    p.add_argument("entity_type")
    p.add_argument("entity_id", type=int)
    p.add_argument("tag")
    p.add_argument("--note")
    p.set_defaults(func=core.cmd_tag_add)

    p = subparsers.add_parser("tag-remove", help="Remove a tag from an item")
    p.add_argument("program")
    p.add_argument("entity_type")
    p.add_argument("entity_id", type=int)
    p.add_argument("tag")
    p.set_defaults(func=core.cmd_tag_remove)

    p = subparsers.add_parser("tags", help="List tags")
    p.add_argument("program")
    p.add_argument("--entity-type")
    p.add_argument("--tag")
    p.add_argument("--format", choices=["text", "json", "csv"], default="text")
    p.set_defaults(func=core.cmd_tags)
