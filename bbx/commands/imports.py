from bbx import core


def register(subparsers):
    p = subparsers.add_parser("import-har", help="Import a HAR file")
    p.add_argument("program")
    p.add_argument("file")
    p.set_defaults(func=core.cmd_import_har)

    p = subparsers.add_parser("validate-import", help="Validate an import file before ingest")
    p.add_argument("kind", choices=["har", "ffuf", "nuclei", "subfinder", "amass", "httpx", "katana", "gau", "wayback", "naabu"])
    p.add_argument("file")
    p.set_defaults(func=core.cmd_validate_import)

    for name, func, help_text in [
        ("ingest-ffuf", core.cmd_ingest_ffuf, "Import ffuf JSON output"),
        ("ingest-nuclei", core.cmd_ingest_nuclei, "Import nuclei JSONL output"),
        ("ingest-subfinder", core.cmd_ingest_subfinder, "Import subfinder TXT output"),
        ("ingest-amass", core.cmd_ingest_amass, "Import amass TXT output"),
        ("ingest-httpx", core.cmd_ingest_httpx, "Import httpx JSONL output"),
        ("ingest-katana", core.cmd_ingest_katana, "Import katana output"),
        ("ingest-gau", core.cmd_ingest_gau, "Import gau TXT output"),
        ("ingest-wayback", core.cmd_ingest_wayback, "Import wayback URLs TXT output"),
        ("ingest-naabu", core.cmd_ingest_naabu, "Import naabu TXT output"),
    ]:
        sp = subparsers.add_parser(name, help=help_text)
        sp.add_argument("program")
        sp.add_argument("file")
        sp.set_defaults(func=func)
