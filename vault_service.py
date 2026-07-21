from pathlib import Path
from secrets import compare_digest

from Password_vault import PasswordVault


class MasterPasswordMismatchError(ValueError):
    """Las dos contraseñas maestras no coinciden."""


class VaultService:
    """Coordina el ciclo de creación y desbloqueo del vault."""

    def __init__(self, file_path: str | Path = "vault.enc") -> None:
        self._file_path = Path(file_path)

    @property
    def exists(self) -> bool:
        return self._file_path.is_file()

    def create(
        self,
        master_password: str,
        confirmation: str,
    ) -> PasswordVault:
        if not compare_digest(master_password, confirmation):
            raise MasterPasswordMismatchError(
                "Las contraseñas maestras no coinciden."
            )

        vault = PasswordVault(self._file_path)
        vault.create(master_password)
        return vault

    def unlock(self, master_password: str) -> PasswordVault:
        vault = PasswordVault(self._file_path)
        vault.unlock(master_password)
        return vault