from .json_db import JSONDatabase
from .sqlite_db import SQLiteDatabase


def get_database():
    """Return the configured datastore (json | sqlite)."""
    from utils.config import get_settings
    settings = get_settings()
    backend = (getattr(settings, "db_backend", "json") or "json").lower()
    if backend == "sqlite":
        return SQLiteDatabase(getattr(settings, "db_path", None))
    return JSONDatabase()


__all__ = ["JSONDatabase", "SQLiteDatabase", "get_database"]
