from __future__ import annotations

import argparse
import json
import multiprocessing
from importlib import resources
from pathlib import Path

from .config import load_config
from .core.models import ReviewStatus
from .core.registry import default_registry
from .service import SentinalService
from .scheduler import PollScheduler
from .web import serve


def parser() -> argparse.ArgumentParser:
    registry = default_registry()
    root = argparse.ArgumentParser(prog="sentinal", description="Local program and repository change monitoring")
    root.add_argument("--config", default="config.toml", help="path to TOML configuration")
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="initialize configuration and database")
    poll = commands.add_parser("poll", help="poll configured sources once")
    poll.add_argument("--source", choices=("all", *registry.source_types()), default="all")
    poll.add_argument("--fail-fast", action="store_true")
    serve_command = commands.add_parser("serve", help="serve dashboard and JSON API")
    serve_command.add_argument("--host")
    serve_command.add_argument("--port", type=int)
    run_command = commands.add_parser("run", help="run local dashboard with automatic monitoring")
    run_command.add_argument("--host")
    run_command.add_argument("--port", type=int)
    mcp = commands.add_parser("mcp", help="provide local monitoring data to MCP agents over stdio")
    mcp.add_argument("--enable-queue", action="store_true", help="allow MCP agents to queue manual checks (opt-in)")
    events = commands.add_parser("events", help="print recorded changes as JSON")
    events.add_argument("--status", choices=tuple(status.value for status in ReviewStatus))
    events.add_argument("--limit", type=int, default=50)
    return root


def main(argv=None) -> int:
    multiprocessing.freeze_support()
    return _main(argv)


def _main(argv: list[str] | None = None) -> int:
    cli = parser()
    args = cli.parse_args(argv)
    config_path = Path(args.config)
    if not config_path.exists() and args.command in ("init", "run", "serve"):
        example = resources.files("sentinal").joinpath("defaults", "config.example.toml")
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_bytes(example.read_bytes())
        print(f"Created {config_path}. Review it before polling external sources.")
    elif not config_path.is_file():
        cli.error(f"Configuration not found: {config_path}. Run sentinal --config {config_path} init first.")

    config = load_config(config_path)
    service = SentinalService(config)
    try:
        return _run_command(args, config, service)
    finally:
        service.onchain.close()
        close = getattr(service.client, 'close', None)
        if callable(close):
            close()


def _run_command(args, config, service) -> int:
    if args.command == "init":
        service.initialize()
        print(f"Database ready: {config.database}")
        return 0
    if args.command == "poll":
        result = service.poll(args.source, args.fail_fast)
        print(json.dumps({"inserted": result.inserted, "duplicates": result.duplicates, "errors": result.errors}, indent=2))
        return 1 if result.errors else 0
    if args.command == "serve":
        serve(service.store, args.host or config.server_host, args.port or config.server_port, on_start=service.initialize, onchain=service.onchain)
        return 0
    if args.command == "run":
        scheduler = PollScheduler(service)
        try:
            serve(
                service.store,
                args.host or config.server_host,
                args.port or config.server_port,
                scheduler, on_start=scheduler.start, onchain=service.onchain,
            )
        finally:
            if scheduler.running:
                scheduler.stop()
        return 0
    if args.command == "mcp":
        # Do not silently create a database or scheduler when an agent connects.
        if not config.database.is_file():
            cli_message = f"Monitoring database not found: {config.database}. Run sentinal init first."
            raise SystemExit(cli_message)
        from .mcp_server import serve_mcp
        service.store.initialize()
        serve_mcp(service.store, enable_queue=args.enable_queue)
        return 0
    if args.command == "events":
        service.initialize()
        print(json.dumps(service.store.list_events(status=args.status, limit=args.limit), indent=2))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
