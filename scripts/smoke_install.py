"""Verify a wheel's resources, first-run initialization and isolated local server."""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import tomllib
import venv
from pathlib import Path
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener


def run(args, cwd):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheel-dir', required=True, type=Path)
    args = parser.parse_args()
    wheels = sorted(args.wheel_dir.resolve().glob('sentinal_pro-*.whl'))
    if len(wheels) != 1:
        raise SystemExit('Use a directory containing exactly one sentinal-pro wheel.')
    with tempfile.TemporaryDirectory(prefix='sentinal-wheel-') as scratch:
        root = Path(scratch)
        environment = root / 'isolated environment'
        venv.EnvBuilder(with_pip=True).create(environment)
        python = environment / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
        run([str(python), '-m', 'pip', 'install', '--no-index', '--no-deps', str(wheels[0])], root)
        workspace = root / 'fresh workspace'
        workspace.mkdir()
        run([str(python), '-I', '-m', 'sentinal', 'init'], workspace)
        config = workspace / 'config.toml'
        defaults = tomllib.loads(config.read_text(encoding='utf-8'))
        assert defaults['server']['host'] == '127.0.0.1'
        assert not defaults.get('protocols'), 'First run enabled placeholder targets.'
        assert (workspace / 'sentinal.db').exists()
        # Disposable smoke checks must never contact external sources.
        config.write_text('database = "sentinal.db"\n[global_jobs.catalog]\nenabled = false\n', encoding='utf-8')
        # MCP must work from the installed wheel without build-time imports or
        # a running HTTP server. A tool response must contain only protocol JSON.
        handshake = '\n'.join(json.dumps(message) for message in (
            {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
                'protocolVersion': '2025-11-25', 'capabilities': {},
                'clientInfo': {'name': 'wheel-smoke', 'version': '1'}}},
            {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'},
        )) + '\n'
        mcp = subprocess.run([str(python), '-I', '-m', 'sentinal', 'mcp'], cwd=workspace,
                             input=handshake, capture_output=True, text=True, timeout=15)
        assert mcp.returncode == 0, mcp.stderr
        replies = [json.loads(line) for line in mcp.stdout.splitlines()]
        assert len(replies) == 2, mcp.stdout
        assert replies[0]['result']['protocolVersion'] == '2025-11-25'
        assert 'get_file_patch' in {tool['name'] for tool in replies[1]['result']['tools']}
        assert 'queue_check' not in {tool['name'] for tool in replies[1]['result']['tools']}
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            port = reserved.getsockname()[1]
        opener = build_opener(ProxyHandler({}))
        with (root / 'server.log').open('w+', encoding='utf-8') as log:
            process = subprocess.Popen([str(python), '-I', '-m', 'sentinal', 'run', '--port', str(port)],
                                       cwd=workspace, stdout=log, stderr=subprocess.STDOUT)
            try:
                origin = f'http://127.0.0.1:{port}'
                deadline = time.monotonic() + 20
                while True:
                    if process.poll() is not None:
                        log.seek(0)
                        raise RuntimeError('Local startup failed:\n' + log.read())
                    try:
                        with opener.open(origin + '/api/health', timeout=1) as response:
                            assert json.load(response)['status'] == 'ok'
                        break
                    except (URLError, TimeoutError):
                        if time.monotonic() >= deadline:
                            raise RuntimeError('Local server did not become healthy.')
                        time.sleep(0.1)
                for asset in ('dashboard.css', 'dashboard.js', 'research.js'):
                    with opener.open(origin + '/static/' + asset, timeout=3) as response:
                        assert response.read(), f'Packaged asset missing: {asset}'
                with opener.open(origin + '/api/programs', timeout=3) as response:
                    assert json.load(response)['programs'] == []
                with opener.open(origin + '/api/status', timeout=3) as response:
                    assert json.load(response)['running'] is True
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        print('Installed wheel: initialization, MCP stdio, packaged assets, loopback API and scheduler passed; temporary server stopped.')


if __name__ == '__main__':
    main()
