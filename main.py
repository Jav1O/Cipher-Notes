"""Punto de entrada de CipherNotes."""

from pathlib import Path

from cli import run_cli
from models import StorageError
from storage import Storage


def main() -> int:
    db_path = Path(__file__).resolve().parent / ".local" / "ciphernotes.db"
    try:
        storage = Storage(db_path)
        storage.init_db()
        run_cli(storage)
    except StorageError as error:
        print(error)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nCipherNotes cerrado.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
