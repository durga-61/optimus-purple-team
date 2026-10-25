#!/usr/bin/env python3
"""Fetch and prepare the University of Hohenheim cold-storage dataset.

Downloads ``Preprocessed.zip`` from Zenodo record 15130001 (CC-BY-4.0), verifies
its MD5 against ``data/DATASET_MANIFEST.json``, extracts the nine per-sensor CSVs
and builds the SQLite replay cache used by ``HohenheimDataSource``.

Usage:
    python scripts/fetch_dataset.py            # download + build (idempotent)
    python scripts/fetch_dataset.py --force    # re-download and rebuild
    python scripts/fetch_dataset.py --no-build # download only, skip SQLite build
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Make ``app`` importable when this script is executed directly.
sys.path.insert(0, str(ROOT))

ZENODO_RECORD = "15130001"
ZENODO_PAGE = f"https://zenodo.org/records/{ZENODO_RECORD}"
ARCHIVE_URL = f"https://zenodo.org/api/records/{ZENODO_RECORD}/files/Preprocessed.zip/content"
ARCHIVE_NAME = "Preprocessed.zip"
MANIFEST_PATH = ROOT / "data" / "DATASET_MANIFEST.json"
EXPECTED_SENSORS = [f"SENSOR0{i}_preprocessed.csv" for i in range(1, 10)]


def _fail(message: str, code: int = 1) -> None:
    print(f"\n[ERROR] {message}", file=sys.stderr)
    raise SystemExit(code)


def _manifest_checksum() -> tuple[str | None, int | None]:
    """Return the expected (md5, size) for the archive from the dataset manifest."""
    if not MANIFEST_PATH.exists():
        return None, None
    try:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        entry = manifest.get("file_manifest", {}).get(ARCHIVE_NAME, {})
        return entry.get("md5"), entry.get("size_bytes")
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[warn] Could not read {MANIFEST_PATH}: {exc}", file=sys.stderr)
        return None, None


def _md5(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(url: str, destination: Path) -> None:
    """Download ``url`` to ``destination`` with a simple progress indicator."""
    request = urllib.request.Request(url, headers={"User-Agent": "optimus-dataset-fetch/1.0"})
    print(f"Downloading {url}\n  -> {destination}")
    with urllib.request.urlopen(request, timeout=60) as response:
        total = int(response.headers.get("Content-Length") or 0)
        downloaded = 0
        started = time.monotonic()
        with destination.open("wb") as handle:
            while True:
                chunk = response.read(256 * 1024)
                if not chunk:
                    break
                handle.write(chunk)
                downloaded += len(chunk)
                if total:
                    pct = downloaded * 100 / total
                    sys.stdout.write(
                        f"\r  {downloaded / 1e6:6.2f} / {total / 1e6:6.2f} MB ({pct:5.1f}%)"
                    )
                    sys.stdout.flush()
        elapsed = max(time.monotonic() - started, 1e-6)
        print(f"\r  {downloaded / 1e6:6.2f} MB in {elapsed:.1f}s{' ' * 24}")


def _extract(archive: Path, target_dir: Path) -> None:
    """Extract the nine sensor CSVs into ``target_dir``, rejecting unsafe members."""
    target_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as bundle:
        names = {Path(name).name: name for name in bundle.namelist() if not name.endswith("/")}
        missing = [name for name in EXPECTED_SENSORS if name not in names]
        if missing:
            _fail(f"Archive is missing expected sensor files: {', '.join(missing)}")
        for name in EXPECTED_SENSORS:
            member = names[name]
            if Path(member).is_absolute() or ".." in Path(member).parts:
                _fail(f"Refusing unsafe archive member: {member}")
            with bundle.open(member) as source, (target_dir / name).open("wb") as sink:
                shutil.copyfileobj(source, sink)
    print(f"Extracted {len(EXPECTED_SENSORS)} sensor files into {target_dir}")


def _build_cache() -> None:
    """Build the SQLite replay cache by instantiating the data source once."""
    from app.data_sources.hohenheim import HohenheimDataSource

    print("Building SQLite replay cache (this takes a few seconds)...")
    source = HohenheimDataSource()
    try:
        print(f"Ready: {source.total_records:,} synchronized observations at {source.db_path}")
    finally:
        source.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--force", action="store_true", help="Re-download and rebuild even if the dataset is present")
    parser.add_argument("--no-build", action="store_true", help="Download and extract only; skip the SQLite cache build")
    args = parser.parse_args()

    from app.config import settings
    from app.data_sources.hohenheim import dataset_paths, hohenheim_dataset_available

    db_path, raw_dir = dataset_paths()
    preprocessed_dir = raw_dir / "preprocessed"

    if hohenheim_dataset_available() and not args.force:
        print(f"Dataset already prepared ({db_path.name} present). Nothing to do. Use --force to rebuild.")
        return

    raw_dir.mkdir(parents=True, exist_ok=True)
    archive = raw_dir / ARCHIVE_NAME
    expected_md5, expected_size = _manifest_checksum()

    if not archive.exists() or args.force:
        try:
            _download(ARCHIVE_URL, archive)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
            archive.unlink(missing_ok=True)
            _fail(
                f"Download failed: {exc}\n"
                "Manual alternative:\n"
                f"  1. Open {ZENODO_PAGE}\n"
                f"  2. Download {ARCHIVE_NAME}\n"
                f"  3. Save it to {archive}\n"
                "  4. Re-run: python scripts/fetch_dataset.py",
                code=2,
            )

    size = archive.stat().st_size
    if expected_size and size != expected_size:
        _fail(f"Size mismatch for {archive.name}: got {size} bytes, expected {expected_size}. Re-run with --force.")
    actual_md5 = _md5(archive)
    if expected_md5 and actual_md5 != expected_md5:
        _fail(
            f"MD5 mismatch for {archive.name}: got {actual_md5}, expected {expected_md5}. "
            "The download is corrupt; re-run with --force."
        )
    print(f"Checksum OK ({actual_md5}, {size:,} bytes)")

    _extract(archive, preprocessed_dir)

    for required in ("experiment_actions.csv", "overview.csv"):
        if not (raw_dir / required).exists():
            print(f"[warn] {required} is missing from {raw_dir}; git checkout it if needed.", file=sys.stderr)

    if args.no_build:
        print(f"Skipping SQLite build. Next: build it or run the app (mode={settings.DATA_SOURCE_MODE}).")
        return

    _build_cache()


if __name__ == "__main__":
    main()
