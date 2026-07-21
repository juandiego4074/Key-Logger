from __future__ import annotations

import base64
import json
import os
import stat
import uuid

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class VaultError(Exception):
    """Error general del vault."""


class VaultAuthenticationError(VaultError):
    """Contraseña incorrecta o archivo alterado."""


class VaultNotUnlockedError(VaultError):
    """Se intentó usar el vault sin desbloquearlo."""


class PasswordVault:
    VERSION = 1

    # Parámetros de Scrypt.
    KDF_N = 2**15
    KDF_R = 8
    KDF_P = 1

    SALT_SIZE = 16
    NONCE_SIZE = 12
    KEY_SIZE = 32

    ASSOCIATED_DATA = b"password-vault:v1"

    def __init__(self, file_path: str | Path = "vault.enc") -> None:
        self.file_path = Path(file_path)

        self._salt: bytes | None = None
        self._key: bytes | None = None
        self._data: dict[str, Any] = {
            "version": self.VERSION,
            "entries": [],
        }

    @property
    def is_unlocked(self) -> bool:
        return self._key is not None

    def create(self, master_password: str) -> None:
        """Crea un vault cifrado nuevo."""

        if self.file_path.exists():
            raise FileExistsError(
                f"El vault ya existe: {self.file_path}"
            )

        self._validate_master_password(master_password)

        self._salt = os.urandom(self.SALT_SIZE)
        self._key = self._derive_key(master_password, self._salt)

        self._data = {
            "version": self.VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "entries": [],
        }

        self.save()

    def unlock(self, master_password: str) -> None:
        """Desbloquea y descifra un vault existente."""

        if not self.file_path.exists():
            raise FileNotFoundError(
                f"No existe el vault: {self.file_path}"
            )

        try:
            envelope = json.loads(
                self.file_path.read_text(encoding="utf-8")
            )

            self._validate_envelope(envelope)

            salt = self._decode_base64(envelope["salt"])
            nonce = self._decode_base64(envelope["nonce"])
            ciphertext = self._decode_base64(envelope["ciphertext"])

            key = self._derive_key(master_password, salt)

            plaintext = AESGCM(key).decrypt(
                nonce,
                ciphertext,
                self.ASSOCIATED_DATA,
            )

            data = json.loads(plaintext.decode("utf-8"))
            self._validate_vault_data(data)

        except InvalidTag as error:
            raise VaultAuthenticationError(
                "Contraseña maestra incorrecta o archivo alterado."
            ) from error

        except (
            KeyError,
            ValueError,
            TypeError,
            json.JSONDecodeError,
        ) as error:
            raise VaultError(
                "El archivo del vault tiene un formato inválido."
            ) from error

        self._salt = salt
        self._key = key
        self._data = data

    def save(self) -> None:
        """Cifra y guarda el estado actual del vault."""

        self._require_unlocked()

        if self._salt is None or self._key is None:
            raise VaultNotUnlockedError("El vault no está desbloqueado.")

        plaintext = json.dumps(
            self._data,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

        # AES-GCM requiere un nonce nuevo para cada cifrado con la misma clave.
        nonce = os.urandom(self.NONCE_SIZE)

        ciphertext = AESGCM(self._key).encrypt(
            nonce,
            plaintext,
            self.ASSOCIATED_DATA,
        )

        envelope = {
            "version": self.VERSION,
            "kdf": "scrypt",
            "cipher": "AES-256-GCM",
            "n": self.KDF_N,
            "r": self.KDF_R,
            "p": self.KDF_P,
            "salt": self._encode_base64(self._salt),
            "nonce": self._encode_base64(nonce),
            "ciphertext": self._encode_base64(ciphertext),
        }

        self._atomic_write(envelope)

    def add_entry(
        self,
        service: str,
        username: str,
        password: str,
        notes: str = "",
    ) -> str:
        """Añade una credencial y guarda el vault."""

        self._require_unlocked()

        if not service.strip():
            raise ValueError("El servicio no puede estar vacío.")

        if not password:
            raise ValueError("La contraseña no puede estar vacía.")

        entry_id = uuid.uuid4().hex

        entry = {
            "id": entry_id,
            "service": service.strip(),
            "username": username.strip(),
            "password": password,
            "notes": notes.strip(),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        self._data["entries"].append(entry)
        self.save()

        return entry_id

    def list_entries(self) -> list[dict[str, str]]:
        """Devuelve información sin revelar las contraseñas."""

        self._require_unlocked()

        return [
            {
                "id": entry["id"],
                "service": entry["service"],
                "username": entry["username"],
            }
            for entry in self._data["entries"]
        ]

    def get_entry(self, entry_id: str) -> dict[str, str] | None:
        """Obtiene una entrada completa por su identificador."""

        self._require_unlocked()

        for entry in self._data["entries"]:
            if entry["id"] == entry_id:
                return entry.copy()

        return None

    def delete_entry(self, entry_id: str) -> bool:
        """Elimina una entrada y guarda el vault."""

        self._require_unlocked()

        entries = self._data["entries"]

        for index, entry in enumerate(entries):
            if entry["id"] == entry_id:
                del entries[index]
                self.save()
                return True

        return False

    def lock(self) -> None:
        """Elimina las referencias activas a la clave y los datos."""

        self._key = None
        self._salt = None
        self._data = {
            "version": self.VERSION,
            "entries": [],
        }

    def _derive_key(
        self,
        master_password: str,
        salt: bytes,
    ) -> bytes:
        kdf = Scrypt(
            salt=salt,
            length=self.KEY_SIZE,
            n=self.KDF_N,
            r=self.KDF_R,
            p=self.KDF_P,
        )

        return kdf.derive(master_password.encode("utf-8"))

    def _validate_master_password(
        self,
        master_password: str,
    ) -> None:
        if len(master_password) < 12:
            raise ValueError(
                "La contraseña maestra debe tener al menos "
                "12 caracteres."
            )

    def _require_unlocked(self) -> None:
        if not self.is_unlocked:
            raise VaultNotUnlockedError(
                "Primero debe desbloquear el vault."
            )

    def _validate_envelope(
        self,
        envelope: dict[str, Any],
    ) -> None:
        if envelope.get("version") != self.VERSION:
            raise VaultError("Versión de vault no compatible.")

        if envelope.get("kdf") != "scrypt":
            raise VaultError("KDF no compatible.")

        if envelope.get("cipher") != "AES-256-GCM":
            raise VaultError("Algoritmo de cifrado no compatible.")

        # Evita aceptar parámetros manipulados o inesperados.
        if envelope.get("n") != self.KDF_N:
            raise VaultError("Parámetros Scrypt inválidos.")

        if envelope.get("r") != self.KDF_R:
            raise VaultError("Parámetros Scrypt inválidos.")

        if envelope.get("p") != self.KDF_P:
            raise VaultError("Parámetros Scrypt inválidos.")

    def _validate_vault_data(
        self,
        data: dict[str, Any],
    ) -> None:
        if not isinstance(data, dict):
            raise VaultError("Contenido interno inválido.")

        if data.get("version") != self.VERSION:
            raise VaultError("Versión interna inválida.")

        if not isinstance(data.get("entries"), list):
            raise VaultError("La lista de entradas es inválida.")

    @staticmethod
    def _encode_base64(value: bytes) -> str:
        return base64.b64encode(value).decode("ascii")

    @staticmethod
    def _decode_base64(value: str) -> bytes:
        return base64.b64decode(value, validate=True)

    def _atomic_write(
        self,
        envelope: dict[str, Any],
    ) -> None:
        temporary_path = self.file_path.with_suffix(
            self.file_path.suffix + ".tmp"
        )

        serialized = json.dumps(
            envelope,
            indent=2,
            ensure_ascii=False,
        )

        with temporary_path.open("w", encoding="utf-8") as file:
            file.write(serialized)
            file.flush()
            os.fsync(file.fileno())

        os.replace(temporary_path, self.file_path)

        # Funciona principalmente en Linux/macOS.
        # En Windows los permisos se administran de otra manera.
        try:
            os.chmod(
                self.file_path,
                stat.S_IRUSR | stat.S_IWUSR,
            )
        except OSError:
            pass