"""enforcement-mcp: SELinux, fapolicyd, and MLS policy intelligence for LLM agents."""

import argparse
import os

__version__ = "0.5.2"


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="enforcement-mcp — SELinux/fapolicyd/MLS policy intelligence",
    )
    sub = parser.add_subparsers(dest="command")

    # Default: run the MCP server (also when no subcommand given)
    serve_parser = sub.add_parser("serve", help="Run the MCP server (default)")
    serve_parser.add_argument(
        "target",
        nargs="?",
        help="Default target RHEL host (overrides ENFORCEMENT_MCP_TARGET env var)",
    )
    serve_parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
    )
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8100)
    serve_parser.add_argument(
        "--escalation-passphrase",
        help="Enable sudo-like escalation for management tools. "
        "Model must call manage.escalate with this passphrase to unlock mutating tools.",
    )
    serve_parser.add_argument(
        "--escalation-timeout",
        type=int,
        default=1800,
        help="Seconds before escalation expires (default: 1800 = 30 min)",
    )

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
    passphrase = getattr(args, "escalation_passphrase", None)
    if passphrase:
        os.environ["ENFORCEMENT_MCP_TOOL_TIER"] = "management"

    from .server import mcp, set_default_target, set_escalation_config

    target = getattr(args, "target", None)
    if target:
        set_default_target(target)

    if passphrase:
        timeout = getattr(args, "escalation_timeout", 1800)
        set_escalation_config(passphrase, timeout)

    transport = getattr(args, "transport", "stdio")
    if transport == "stdio":
        mcp.run()
    else:
        mcp.run(
            transport=transport,
            host=getattr(args, "host", "127.0.0.1"),
            port=getattr(args, "port", 8100),
        )
