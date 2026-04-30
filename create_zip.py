from __future__ import annotations

import argparse
import os
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path


def list_files(repo_root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=repo_root,
        check=True,
        capture_output=True,
    )
    files: list[Path] = []
    for raw_path in result.stdout.split(b"\0"):
        if not raw_path:
            continue
        relative = Path(raw_path.decode("utf-8"))
        absolute = repo_root / relative
        if absolute.is_file():
            files.append(relative)
    return files


def create_zip(repo_root: Path, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    repo_relative_output = output_path.relative_to(repo_root) if output_path.is_relative_to(repo_root) else None
    files = list_files(repo_root)
    if repo_relative_output is not None:
        files = [path for path in files if path != repo_relative_output]

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative_path in files:
            archive.write(repo_root / relative_path, arcname=relative_path.as_posix())

    return output_path


def parse_args(repo_root: Path) -> argparse.Namespace:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    default_output = repo_root / "dist" / f"{repo_root.name}-{timestamp}.zip"

    parser = argparse.ArgumentParser(
        description="Create a zip archive using git-tracked and non-ignored files."
    )
    parser.add_argument(
        "output",
        nargs="?",
        default=str(default_output),
        help=f"Output zip path. Default: {default_output}",
    )
    return parser.parse_args()


def main() -> int:
    repo_root = Path(__file__).resolve().parent
    args = parse_args(repo_root)
    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = repo_root / output_path

    try:
        created = create_zip(repo_root, output_path)
    except subprocess.CalledProcessError as error:
        print(error.stderr.decode("utf-8", errors="replace"), file=sys.stderr)
        return error.returncode or 1
    except Exception as error:  # pragma: no cover - CLI surface
        print(f"create_zip failed: {error}", file=sys.stderr)
        return 1

    print(created)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
