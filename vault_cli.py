from getpass import getpass
from pathlib import Path

from Password_vault import (
    PasswordVault,
    VaultAuthenticationError,
    VaultError,
)


VAULT_FILE = Path("vault.enc")


def open_vault() -> PasswordVault:
    vault = PasswordVault(VAULT_FILE)

    if VAULT_FILE.exists():
        print("Introduzca la contraseña maestra.")
        print("La contraseña no aparecerá mientras escribe.")

        master_password = getpass("> ")

        try:
            vault.unlock(master_password)

        except VaultAuthenticationError:
            print(
                "Contraseña incorrecta o archivo alterado."
            )
            raise SystemExit(1)
        except VaultError as error:
            print(f"No se pudo abrir el vault: {error}")
            raise SystemExit(1)

        print("Vault desbloqueado.")
        return vault

    print("No existe un vault. Se creará uno nuevo.")
    print("Cree una contraseña maestra de al menos 12 caracteres.")
    print("La contraseña no aparecerá mientras escribe.")

    master_password = getpass("> ")

    print("Confirme la contraseña maestra.")
    confirmation = getpass("> ")

    if master_password != confirmation:
        print("Las contraseñas no coinciden.")
        raise SystemExit(1)

    try:
        vault.create(master_password)

    except ValueError as error:
        print(f"No se pudo crear el vault: {error}")
        raise SystemExit(1)

    print("Vault creado correctamente.")
    return vault





def show_entries(vault: PasswordVault) -> None:
    entries = vault.list_entries()

    if not entries:
        print("\nEl vault está vacío.")
        return

    print("\nEntradas guardadas:")

    for index, entry in enumerate(entries, start=1):
        print(
            f"{index}. {entry['service']} | "
            f"{entry['username']} | "
            f"ID: {entry['id']}"
        )


def add_entry(vault: PasswordVault) -> None:
    service = input("Servicio: ").strip()
    username = input("Usuario o correo: ").strip()
    password = getpass("Contraseña que desea guardar: ")
    notes = input("Notas opcionales: ").strip()

    try:
        entry_id = vault.add_entry(
            service=service,
            username=username,
            password=password,
            notes=notes,
        )
    except ValueError as error:
        print(f"No se pudo guardar: {error}")
        return

    print(f"Entrada guardada. ID: {entry_id}")


def reveal_entry(vault: PasswordVault) -> None:
    entry_id = input("ID de la entrada: ").strip()
    entry = vault.get_entry(entry_id)

    if entry is None:
        print("No se encontró esa entrada.")
        return

    print(f"\nServicio: {entry['service']}")
    print(f"Usuario: {entry['username']}")
    print(f"Contraseña: {entry['password']}")
    print(f"Notas: {entry['notes']}")


def delete_entry(vault: PasswordVault) -> None:
    entry_id = input("ID de la entrada: ").strip()

    confirmation = input(
        "¿Eliminar permanentemente? (s/n): "
    ).strip().lower()

    if confirmation != "s":
        print("Operación cancelada.")
        return

    if vault.delete_entry(entry_id):
        print("Entrada eliminada.")
    else:
        print("No se encontró esa entrada.")


def main() -> None:
    vault = open_vault()

    try:
        while True:
            print(
                "\nPassword Vault\n"
                "1. Añadir entrada\n"
                "2. Listar entradas\n"
                "3. Mostrar una contraseña\n"
                "4. Eliminar entrada\n"
                "5. Bloquear y salir"
            )

            option = input("> ").strip()

            if option == "1":
                add_entry(vault)

            elif option == "2":
                show_entries(vault)

            elif option == "3":
                reveal_entry(vault)

            elif option == "4":
                delete_entry(vault)

            elif option == "5":
                break

            else:
                print("Seleccione una opción válida.")

    finally:
        vault.lock()
        print("Vault bloqueado.")


if __name__ == "__main__":
    main()