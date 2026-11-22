"""Menús de consola de CipherNotes."""

import warnings
from getpass import GetPassWarning, getpass

from auth import login, register
from models import CipherNotesError, IntegrityError, Session, ValidationError
from service import create_note, list_notes, open_note, verify_note_signature
from storage import Storage


def _password(prompt: str) -> str:
    with warnings.catch_warnings():
        warnings.simplefilter("error", GetPassWarning)
        try:
            return getpass(prompt)
        except GetPassWarning as error:
            raise ValidationError("Abre una terminal para introducir la contraseña sin mostrarla.") from error


def _read_body() -> str:
    print("Escribe el contenido. Pon un punto solo en una línea para terminar.")
    lines = []
    char_count = 0
    while (line := input()) != ".":
        char_count += len(line) + 1
        if char_count > 20_001:
            raise ValidationError("La nota supera los 20 000 caracteres.")
        lines.append(line)
    return "\n".join(lines)


def _session_menu(storage: Storage, session: Session) -> None:
    print(f"Sesión iniciada como {session.username}.")
    while True:
        print("\n1. Crear nota\n2. Listar notas\n3. Leer nota\n4. Verificar firma\n5. Cerrar sesión")
        choice = input("Elige una opción: ").strip()
        try:
            if choice == "1":
                title = input("Título: ")
                note_id = create_note(storage, session, title, _read_body())
                print(f"Nota cifrada con AES-256-GCM y firmada con RSA-PSS. ID: {note_id}")
            elif choice == "2":
                records = list_notes(storage, session)
                if not records:
                    print("Aún no tienes notas.")
                for record in records:
                    try:
                        title, _ = open_note(storage, session, record.id)
                        print(f"{record.id}  {title}")
                    except (IntegrityError, ValidationError) as error:
                        print(f"{record.id!r}  Nota rechazada. {error}")
            elif choice == "3":
                note_id = input("ID de la nota: ").strip()
                title, body = open_note(storage, session, note_id)
                print(f"Firma RSA-PSS y tag AES-GCM válidos.\nTítulo: {title}\n{body}")
            elif choice == "4":
                note_id = input("ID de la nota: ").strip()
                if verify_note_signature(storage, session, note_id):
                    print("Firma RSA-PSS válida.")
                else:
                    print("Firma RSA-PSS inválida. Se rechaza la nota.")
            elif choice == "5":
                print("Sesión cerrada.")
                return
            else:
                print("Opción inválida.")
        except CipherNotesError as error:
            print(f"Operación rechazada. {error}")


def run_cli(storage: Storage) -> None:
    print("CipherNotes")
    while True:
        print("\n1. Registrarse\n2. Iniciar sesión\n3. Salir")
        choice = input("Elige una opción: ").strip()
        try:
            if choice == "1":
                username = input("Usuario: ")
                password = _password("Contraseña: ")
                try:
                    if password != _password("Repite la contraseña: "):
                        raise ValidationError("Las contraseñas no coinciden.")
                    register(storage, username, password)
                finally:
                    del password
                print("Cuenta creada. Ya puedes iniciar sesión.")
            elif choice == "2":
                username = input("Usuario: ")
                _session_menu(storage, login(storage, username, _password("Contraseña: ")))
            elif choice == "3":
                return
            else:
                print("Opción inválida.")
        except CipherNotesError as error:
            print(f"Operación rechazada. {error}")
