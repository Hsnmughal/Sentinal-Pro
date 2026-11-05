"""Check the publishable tree; optionally create a source ZIP without history."""
from __future__ import annotations

import argparse
import subprocess
import tomllib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def git(*args, input=None):
    return subprocess.run(['git', '-c', 'core.fsmonitor=false', *args], cwd=ROOT,
                          input=input, capture_output=True, check=False)


def paths(*args):
    result = git('ls-files', *args, '-z')
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors='replace'))
    return set(filter(None, result.stdout.decode().split('\0')))


def ignored(names):
    result = git('check-ignore', '--no-index', '-z', '--stdin',
                 input=('\0'.join(sorted(names)) + '\0').encode())
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.decode(errors='replace'))
    return set(filter(None, result.stdout.decode().split('\0')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-zip', type=Path)
    args = parser.parse_args()
    tracked = paths('--cached')
    unwanted = tracked & ignored(tracked)
    if unwanted:
        raise SystemExit('Ignored local files are still Git-tracked:\n' + '\n'.join(sorted(unwanted)))
    metadata = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))
    if metadata['project']['license'] != 'PolyForm-Noncommercial-1.0.0' or not (ROOT / 'LICENSE').is_file():
        raise SystemExit('License metadata and LICENSE must agree before release.')
    if (ROOT / 'config.example.toml').read_bytes() != (ROOT / 'sentinal/defaults/config.example.toml').read_bytes():
        raise SystemExit('The example and packaged default configuration differ.')
    print('Release tree checks passed. Git history must be reviewed separately.')
    if args.source_zip:
        names = paths('--cached', '--others', '--exclude-standard')
        names -= ignored(names)
        destination = args.source_zip.resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name in sorted(names):
                file = ROOT / name
                if not file.resolve().is_relative_to(ROOT):
                    raise SystemExit(f'Source path escapes the checkout: {name}')
                if file.is_file() and file.resolve() != destination:
                    archive.write(file, 'sentinal-pro/' + name)
        print(f'Created source archive without Git history: {destination}')


if __name__ == '__main__':
    main()
