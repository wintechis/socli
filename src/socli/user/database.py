import aiofiles
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from loguru import logger
from serde import serde, Untagged, field
from serde.toml import from_toml, to_toml


@serde
class Token:
    id: str
    secret: str
    resource: str


@serde
class User:
    role: str
    email: str
    webid: str
    password: str
    oidc: str
    token: Token | None


class DatabaseCache:
    """Thread-safe in-memory cache for database operations."""

    def __init__(self, ttl_seconds: int = 300):  # 5 minutes default TTL
        self._cache: dict[str, tuple["UserDB", datetime]] = {}
        self._ttl = timedelta(seconds=ttl_seconds)
        self._lock = threading.RLock()  # Reentrant lock for thread safety

    def get(self, path: str) -> Optional["UserDB"]:
        """Get cached database if not expired."""
        with self._lock:
            if path in self._cache:
                db, timestamp = self._cache[path]
                if datetime.now() - timestamp < self._ttl:
                    logger.debug(f"Cache hit for {path}")
                    return db
                else:
                    logger.debug(f"Cache expired for {path}")
                    del self._cache[path]
            return None

    def set(self, path: str, db: "UserDB") -> None:
        """Cache the database."""
        with self._lock:
            self._cache[path] = (db, datetime.now())
            logger.debug(f"Cached database for {path}")

    def invalidate(self, path: str) -> None:
        """Invalidate cache for a specific path."""
        with self._lock:
            if path in self._cache:
                del self._cache[path]
                logger.debug(f"Cache invalidated for {path}")


@serde(tagging=Untagged)
class UserDB:
    """Database of users with their roles and tokens."""

    users: list[User]
    _index: dict[str, User] = field(default_factory=dict, init=False, skip=True)
    _cache: DatabaseCache = field(default_factory=DatabaseCache, init=False, skip=True)

    def __post_init__(self):
        self._index = {user.role: user for user in self.users}
        self._cache = DatabaseCache()

    def get_user_by_role(self, role: str) -> User | None:
        return self._index.get(role)

    @classmethod
    async def get_user_by_role_from_file(
        cls, role: str, database: str = ".db.toml"
    ) -> User | None:
        """Get a user by role from the database file."""
        db = await cls.read_from_file(database)
        return db.get_user_by_role(role)

    def add_user(self, user: User) -> None:
        self.users.append(user)
        self._index[user.role] = user

    def update_user(self, user: User) -> None:
        for i, u in enumerate(self.users):
            if u.role == user.role:
                self.users[i] = user
                self._index[user.role] = user
                break

    @classmethod
    async def read_from_file(cls, path: str, use_cache: bool = True) -> "UserDB":
        """Read the database from a TOML file."""
        if use_cache:
            cached_db = _db_cache.get(path)
            if cached_db:
                return cached_db

        logger.info(f"Reading database from {path}")
        async with aiofiles.open(path, "r") as f:
            toml = await f.read()

        if not toml.strip():
            logger.warning(f"Database file {path} is empty, returning empty database")
            db = cls(users=[])
            if use_cache:
                _db_cache.set(path, db)
            return db

        try:
            db = from_toml(cls, toml)
            if use_cache:
                _db_cache.set(path, db)
            return db
        except Exception as e:
            logger.error(f"Failed to parse database file {path}: {e}")
            raise ValueError(f"Invalid database file format: {e}")

    async def write_to_file(self, path: str) -> None:
        """Write the database to a TOML file."""
        logger.info(f"Writing database to {path}")
        async with aiofiles.open(path, "w") as f:
            await f.write(to_toml(self))

        _db_cache.invalidate(path)

    @classmethod
    async def add_user_to_file(cls, new_user: User, path: str) -> "UserDB":
        """Add a new user to the database if they don't already exist."""
        if not Path(path).exists():
            logger.info(f"Database file {path} doesn't exist, creating empty database")
            db = cls(users=[])
        else:
            db = await cls.read_from_file(path)

        if db.get_user_by_role(new_user.role):
            raise ValueError(
                f"User with role '{new_user.role}' already exists in the database."
            )

        logger.info(f"Adding user {new_user.role} to the database.")
        db.add_user(new_user)

        return db


_db_cache = DatabaseCache()
