import secrets
import string
from vault_service import VaultService
SIMBOLOS = "!@#$%^&*()-_=+"


def generar_password(longitud: int = 16) -> str:
    if longitud < 12:
        raise ValueError("La longitud mínima debe ser 12 caracteres.")

    grupos = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        SIMBOLOS,
    ]

    # Garantiza al menos un carácter de cada grupo.
    caracteres = [secrets.choice(grupo) for grupo in grupos]

    alfabeto = "".join(grupos)

    caracteres.extend(
        secrets.choice(alfabeto)
        for _ in range(longitud - len(caracteres))
    )

    # Evita que los primeros cuatro caracteres tengan un orden predecible.
    secrets.SystemRandom().shuffle(caracteres)

    return "".join(caracteres)

def save_generated_password(
    password: str,) -> None:
    vault_service = vault_service.VaultService()
    vault = vault_service.open_vault()

    if vault is None:
        print("No se pudo abrir el vault.")
        return

    try:
        service = input("Servicio: ").strip()
        username = input(
            "Usuario o correo: "
        ).strip()
        notes = input(
            "Notas opcionales: "
        ).strip()

        vault.add_entry(
            service=service,
            username=username,
            password=password,
            notes=notes,
        )

        print("Contraseña guardada y cifrada.")

    finally:
        vault.lock()

