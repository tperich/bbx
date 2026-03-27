# Modular layout

The CLI was split into `bbx/commands/` modules for convenience. `bbx.py` remains a tiny entrypoint, `bbx/cli.py` assembles the parser, and `bbx/core.py` holds the current shared command implementation.
