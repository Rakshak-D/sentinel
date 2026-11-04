from pathlib import Path

from sentinel.ingestion import promote_github_fixture_to_public_blobs
from tests.cr1_h1_support import prepared_case


def promoted_case(tmp_path: Path, *, name: str) -> tuple[Path, Path]:
    database, store_root = prepared_case(tmp_path, name=name)
    promote_github_fixture_to_public_blobs(database, store_root=store_root)
    return database, store_root
