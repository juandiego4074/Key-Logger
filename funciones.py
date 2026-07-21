import string
SIMBOLOS = "!@#$%^&*()-_=+"

comunes = {
    "password"
    "qwerty123"
    "secret"
    "qwerty1"
    "12345678"
    "abc123"
    "qwerty"
    "iloveyou"
    "123456"
    "password1"
    "123123"
    "dragón"
}
def security_tips():
    return ('Tips and examples\n\nThe best practices for building passwords within an organization or'
          ' \nfor private password management use are to use a strong password of at least 12 characters and '
          '\nthat effectively combines letters, numbers, and symbols.Avoid using family names,'
          ' \nbank account numbers, birthdays, addresses, Social Security numbers, or other compromising personal '
          '\ninformation. Remember to avoid writing passwords on paper or posting them in your workspace. '
          '\nThis weakens the effectiveness of your password and makes you vulnerable to cyberattacks.\n\n\nexamples of weak and vulnerable passwords'
          '\n* password * secret * 12345678 * qwerty * 123456'
          '\n* qwerty123 * qwerty1 * abc123 * iloveyou * password1'
          ' ')



def password_tester(ask2 : str) -> tuple[bool, list[str]]:
    problemas = []

    if len(ask2) < 12:
        problemas.append("Debe tener al menos 12 caracteres.")
    if not any(c.lower() for c in ask2):
        problemas.append("Falta una letra minúscula.")
    if not any(c.upper() for c in ask2):
        problemas.append("Falta una letra mayúscula.")
    if not any(c.isdigit() for c in ask2):
        problemas.append("Falta un número.")
    if not any(c in SIMBOLOS for c in ask2):
        problemas.append("Falta un símbolo permitido.")
    if ask2.lower() in comunes:
        problemas.append("La contraseña es común o predecible.")


    return not problemas , problemas





