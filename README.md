# Password Generator

Aplicación de consola desarrollada en Python para generar, evaluar y guardar
temporalmente contraseñas.

El proyecto se encuentra en desarrollo y actualmente se utiliza con fines
educativos para practicar programación, seguridad y diseño orientado a objetos.


 [!WARNING]
 Este proyecto es educativo. La versión actual no debe utilizarse para
 almacenar contraseñas reales o información sensible.
 

## Funcionalidades actuales

- Generación automática de contraseñas.
- Evaluación básica de longitud y composición.
- Presentación de recomendaciones de seguridad.
- Almacenamiento temporal de contraseñas durante la ejecución.
- Interfaz interactiva mediante consola.


## Estructura del proyecto

| Archivo                 | Responsabilidad                                                                |
|-------------------------|--------------------------------------------------------------------------------|
| `Ciber_Security-P0.py`  | Punto de entrada, menús y flujo principal                                      |
| `funciones.py`          | Evaluación, consejos, cuentas y funciones del vault                            |
| `Password_Generator.py` | Generación de elementos y contraseñas                                          |
| `docs/`                 | Documentación técnica e ingeniería inversa                                     |
| `Password_vault.py`     | Configuracion del vault y su encriptacion                                      |
| `vault_cli.py`          | Abrir y cerrar el vault independiente base . (Como motivo de estudio del Vult) |
| `vault_service.py`      | Clases del vault del sofware                                                   |


## Requisitos

- Python 3.10 o superior
- `pyfiglet`
- `colorama`
- `cryptography`


Las bibliotecas `secrets`, `string`, `pathlib` y otras bibliotecas estándar
no requieren instalación adicional.


## Instalación

Clona o descarga el proyecto y abre una terminal en su carpeta.

````bash
python -m pip install pyfiglet
python -m pip install colorama
python -m pip install cryptography
```
## Ejecución

Desde la carpeta principal:

```bash
python Ciber_Security-P0.py
````



---

## 8. Explicacion del flujo general

markdown
## Flujo general

text
Inicio
  ↓
Banner
  ↓
Creación de usuario
  ↓
Menú principal
  ├── Generar contraseña
  ├── Mostrar recomendaciones
  ├── Evaluar contraseña
  ├── Guaradar contraseñas en vault
  └── Salir

## Estado actual

La versión actual utiliza programación procedural con ciclos y funciones
distribuidas entre varios módulos.

Las contraseñas guardadas permanecen únicamente en memoria y se pierden al
cerrar el programa.


## Mejoras planificadas

- [x] Sustituir `random` por `secrets`.
- [x] Implementar clases orientadas a objetos.
- [x] Crear un vault persistente cifrado.
- [x] Añadir autenticación mediante contraseña maestra.
- [x] Implementar Scrypt y AES-GCM.
- [x] Corregir la navegación del menú.
- [x] Añadir validación de entradas.
- [x] Añadir pruebas unitarias.


Seguridad

La contraseña maestra nunca debe guardarse directamente en el código ni en archivos de texto plano.

La futura implementación del vault derivará una clave criptográfica desde la contraseña maestra. Los datos se cifrarán antes de escribirse en el disco.

Este proyecto debe considerarse educativo hasta que su implementación sea revisada, probada y auditada.




