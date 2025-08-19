import click
import tomli
import tomli_w

from pathlib import Path
from typing import Optional
from serde.se import serialize
from serde.de import deserialize
from serde.core import field
from loguru import logger


@serialize
@deserialize
class Config:
    """Configuration for socli CLI."""

    default_role: Optional[str] = field(default=None)
    database: str = field(default="./.db.toml")

    @classmethod
    async def read_from_file(cls, path: str = "./.socli.config.toml") -> "Config":
        """Read configuration from TOML file."""
        config_path = Path(path)
        if not config_path.exists():
            logger.debug(f"Config file {path} not found, using defaults")
            return cls()

        try:
            with open(config_path, "rb") as f:
                data = tomli.load(f)
                if "default_role" in data:
                    return cls(
                        default_role=data.get("default_role"),
                        database=data.get("database", "./.db.toml"),
                    )
                return cls()
        except Exception as e:
            logger.warning(f"Failed to read config from {path}: {e}, using defaults")
            return cls()

    async def write_to_file(self, path: str = "./.socli.config.toml") -> None:
        """Write configuration to TOML file."""
        config_path = Path(path)
        try:
            data = {}
            if self.default_role is not None:
                data["default_role"] = self.default_role
            data["database"] = self.database

            toml_str = tomli_w.dumps(data)
            config_path.write_text(toml_str)
            logger.info(f"Config written to {path}")
        except Exception as e:
            logger.error(f"Failed to write config to {path}: {e}")
            raise

    def get_default_role(self) -> Optional[str]:
        """Get the default role if set."""
        return self.default_role

    def set_default_role(self, role: str) -> None:
        """Set the default role."""
        self.default_role = role


async def get_role_with_default(
    role: str | None, config_path: str = "./.socli.config.toml"
) -> str:
    """Get role from parameter or config default."""
    if role:
        return role

    config = await Config.read_from_file(config_path)
    if config.default_role:
        return config.default_role

    click.echo("Error: No role specified and no default role configured.", err=True)
    click.echo(
        "Use -r/--role to specify a role or set a default with 'socli config set-default'",
        err=True,
    )
    raise click.Abort()
