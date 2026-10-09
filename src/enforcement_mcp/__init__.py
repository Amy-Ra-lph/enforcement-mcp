"""enforcement-mcp: SELinux, fapolicyd, and MLS policy intelligence for LLM agents."""

import argparse

__version__ = "0.4.0"


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="enforcement-mcp — SELinux/fapolicyd/MLS policy intelligence",
    )
    sub = parser.add_subparsers(dest="command")

    # Default: run the MCP server (also when no subcommand given)
    serve_parser = sub.add_parser("serve", help="Run the MCP server (default)")
    serve_parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
    )
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8100)

    # setup: configure MCP client
    setup_parser = sub.add_parser(
        "setup", help="Configure your MCP client (Claude Code, Cursor, etc.)",
    )
    setup_parser.add_argument(
        "target", nargs="?", help="Target RHEL host, e.g. webserver01.example.com",
    )

    # check: verify target host prerequisites
    check_parser = sub.add_parser(
        "check", help="Check target host prerequisites (SSH, setools, fapolicyd)",
    )
    check_parser.add_argument("target", nargs="?", help="Target RHEL host to check")

    args = parser.parse_args()

    if args.command == "setup":
        from .cli import cmd_setup
        cmd_setup(args.target)
    elif args.command == "check":
        from .cli import cmd_check
        cmd_check(args.target)
    else:
        _run_server(args)


def _run_server(args: argparse.Namespace) -> None:
    from .server import mcp

    transport = getattr(args, "transport", "stdio")
    if transport == "stdio":
        mcp.run()
    else:
        mcp.run(
            transport=transport,
            host=getattr(args, "host", "127.0.0.1"),
            port=getattr(args, "port", 8100),
        )
