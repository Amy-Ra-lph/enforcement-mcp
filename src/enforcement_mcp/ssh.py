"""SSH backend for executing commands on remote hosts."""

import asyncio
import logging
from dataclasses import dataclass

import paramiko

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    """Result of a remote command execution."""

    stdout: str
    stderr: str
    exit_code: int

    @property
    def success(self) -> bool:
        return self.exit_code == 0

    @property
    def stdout_stripped(self) -> str:
        return self.stdout.strip()


class SSHBackend:
    """Execute commands on remote hosts via SSH."""

    def __init__(
        self,
        host: str,
        user: str = "root",
        port: int = 22,
        key_file: str | None = None,
    ) -> None:
        self.host = host
        self.user = user
        self.port = port
        self.key_file = key_file
        self._client: paramiko.SSHClient | None = None

    async def connect(self) -> None:
        def _connect() -> paramiko.SSHClient:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            kwargs: dict = {
                "hostname": self.host,
                "username": self.user,
                "port": self.port,
            }
            if self.key_file:
                kwargs["key_filename"] = self.key_file
            client.connect(**kwargs)
            return client

        self._client = await asyncio.to_thread(_connect)
        logger.info("Connected to %s@%s:%d", self.user, self.host, self.port)

    async def execute(self, command: str, timeout: int = 30) -> CommandResult:
        if self._client is None:
            raise ConnectionError(f"Not connected to {self.host}")

        def _exec() -> CommandResult:
            assert self._client is not None
            _, stdout, stderr = self._client.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            return CommandResult(
                stdout=stdout.read().decode("utf-8", errors="replace"),
                stderr=stderr.read().decode("utf-8", errors="replace"),
                exit_code=exit_code,
            )

        return await asyncio.to_thread(_exec)

    async def close(self) -> None:
        if self._client:
            self._client.close()
            self._client = None
            logger.info("Disconnected from %s", self.host)
