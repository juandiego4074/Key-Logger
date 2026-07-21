from getpass import getpass

import pyfiglet
from colorama import Fore, init

import funciones
from Password_Generator import generar_password
from Password_vault import (
    PasswordVault,
    VaultAuthenticationError,
    VaultError,
)
from vault_service import (MasterPasswordMismatchError,
    VaultService,
)


VAULT_PATH = "vault.enc"


def show_banner() -> None:
    init(autoreset=True)
    banner = pyfiglet.figlet_format("Password Generator")
    print(Fore.LIGHTBLUE_EX + banner)


def open_vault_interactively() -> PasswordVault | None:
    """Crea o desbloquea el vault sin finalizar la aplicación por errores."""

    service = VaultService(VAULT_PATH)

    if service.exists:
        print("\nIntroduzca la contraseña maestra.")
        print("La contraseña no aparecerá mientras escribe.")
        master_password = getpass("> ")

        try:
            vault = service.unlock(master_password)
        except VaultAuthenticationError:
            print("Contraseña incorrecta o archivo alterado.")
            return None
        except (VaultError, OSError) as error:
            print(f"No se pudo abrir el vault: {error}")
            return None

        print("Vault desbloqueado.")
        return vault

    create = input(
        "\nNo existe un vault. ¿Desea crear uno? (s/n): "
    ).strip().lower()

    if create != "s":
        print("Creación cancelada.")
        return None

    print("Use una contraseña maestra larga, única y de al menos 12 caracteres.")
    master_password = getpass("Contraseña maestra: ")
    confirmation = getpass("Confirme la contraseña: ")

    try:
        vault = service.create(master_password, confirmation)
    except MasterPasswordMismatchError as error:
        print(error)
        return None
    except (ValueError, VaultError, OSError) as error:
        print(f"No se pudo crear el vault: {error}")
        return None

    print("Vault creado y desbloqueado.")
    return vault


def save_generated_password(password: str) -> None:
    """Abre el vault, guarda la contraseña generada y vuelve a bloquearlo."""

    vault = open_vault_interactively()
    if vault is None:
        return

    try:
        service_name = input("Servicio: ").strip()
        username = input("Usuario o correo: ").strip()
        notes = input("Notas opcionales: ").strip()

        entry_id = vault.add_entry(
            service=service_name,
            username=username,
            password=password,
            notes=notes,
        )

        print("Contraseña guardada y cifrada.")
        print(f"ID de la entrada: {entry_id}")
    except (ValueError, VaultError, OSError) as error:
        print(f"No se pudo guardar la contraseña: {error}")
    finally:
        vault.lock()
        print("Vault bloqueado.")


def password_generator_menu() -> None:
    while True:
        print(
            "\nGenerador de contraseñas\n"
            "1. Generar contraseña\n"
            "2. Regresar"
        )
        option = input("> ").strip()

        if option == "1":
            password = generar_password()
            print(f"\nContraseña generada: {password}")

            save = input(
                "¿Desea guardarla en el vault? (s/n): "
            ).strip().lower()

            if save == "s":
                # Se guarda exactamente la contraseña que fue mostrada.
                save_generated_password(password)

        elif option == "2":
            return
        else:
            print("Seleccione una opción válida.")


def password_tester_menu() -> None:
    while True:
        print("\nEvaluador de contraseñas")
        password = getpass("Introduzca una contraseña: ")
        is_secure, problems = funciones.password_tester(password)

        if is_secure:
            print("La contraseña cumple los requisitos básicos.")
        else:
            print("Problemas encontrados:")
            for problem in problems:
                print(f"- {problem}")

        again = input(
            "¿Desea evaluar otra contraseña? (s/n): "
        ).strip().lower()

        if again != "s":
            return


def list_entries(vault: PasswordVault) -> None:
    entries = vault.list_entries()

    if not entries:
        print("\nEl vault está vacío.")
        return

    print("\nEntradas guardadas:")
    for index, entry in enumerate(entries, start=1):
        print(
            f"{index}. {entry['service']} | "
            f"{entry['username']} | ID: {entry['id']}"
        )


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


def add_manual_entry(vault: PasswordVault) -> None:
    service_name = input("Servicio: ").strip()
    username = input("Usuario o correo: ").strip()
    password = getpass("Contraseña que desea guardar: ")
    notes = input("Notas opcionales: ").strip()

    try:
        entry_id = vault.add_entry(
            service=service_name,
            username=username,
            password=password,
            notes=notes,
        )
    except (ValueError, VaultError, OSError) as error:
        print(f"No se pudo guardar: {error}")
        return

    print(f"Entrada guardada y cifrada. ID: {entry_id}")


def delete_entry(vault: PasswordVault) -> None:
    entry_id = input("ID de la entrada: ").strip()
    confirmation = input(
        "¿Eliminar permanentemente esta entrada? (s/n): "
    ).strip().lower()

    if confirmation != "s":
        print("Operación cancelada.")
        return

    try:
        deleted = vault.delete_entry(entry_id)
    except (VaultError, OSError) as error:
        print(f"No se pudo eliminar: {error}")
        return

    print("Entrada eliminada." if deleted else "No se encontró esa entrada.")


def vault_menu() -> None:
    vault = open_vault_interactively()
    if vault is None:
        return

    try:
        while True:
            print(
                "\nPassword Vault\n"
                "1. Listar entradas\n"
                "2. Mostrar una credencial\n"
                "3. Añadir credencial manualmente\n"
                "4. Eliminar credencial\n"
                "5. Bloquear y regresar"
            )
            option = input("> ").strip()

            if option == "1":
                list_entries(vault)
            elif option == "2":
                reveal_entry(vault)
            elif option == "3":
                add_manual_entry(vault)
            elif option == "4":
                delete_entry(vault)
            elif option == "5":
                return
            else:
                print("Seleccione una opción válida.")
    finally:
        vault.lock()
        print("Vault bloqueado.")


def show_main_menu() -> str:
    print(
        "\nMenú principal\n"
        "1. Generar contraseña\n"
        "2. Información y consejos\n"
        "3. Evaluar contraseña\n"
        "4. Password Vault\n"
        "5. Salir"
    )
    return input("> ").strip()


def main() -> None:
    show_banner()

    start = input("Presione Enter para comenzar\n> ")
    if start:
        print("Inicio cancelado.")
        return

    print("\nBienvenido a Password Generator")

    while True:
        option = show_main_menu()

        if option == "1":
            password_generator_menu()
        elif option == "2":
            print("\n" + funciones.security_tips())
        elif option == "3":
            password_tester_menu()
        elif option == "4":
            vault_menu()
        elif option == "5":
            print("Programa finalizado.")
            return
        else:
            print("Seleccione una opción válida.")


if __name__ == "__main__":
    main()