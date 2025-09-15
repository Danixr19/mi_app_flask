# Mi App Flask (educativa) - con 2FA (TOTP)

Proyecto educativo con Flask que incluye:
- Registro y login de usuarios
- Autenticación 2FA basada en TOTP (Google Authenticator / Authy)
- Conexión a MySQL vía SQLAlchemy (PyMySQL)
- Plantillas Jinja2 y CSS profesional

## Qué contiene este ZIP
- `app.py` — aplicación completa (desarrollo)
- `templates/` — plantillas HTML
- `static/style.css` — estilos
- `requirements.txt`
- `.gitignore`
- `.env.example` — ejemplo de variables de entorno (no subir .env al repo)

## Antes de ejecutar
1. Crea la base de datos en tu servidor MySQL / phpMyAdmin (ya mencionaste que lo hiciste).
2. Crea un archivo `.env` en la raíz con las variables:
   ```
   SECRET_KEY=tu_secreto_largo
   DATABASE_USER=root
   DATABASE_PASSWORD=tu_password
   DATABASE_HOST=127.0.0.1
   DATABASE_NAME=mi_app
   ```
3. Instala dependencias:
   ```
   python -m venv venv
   source venv/bin/activate     # o venv\Scripts\activate en Windows
   pip install -r requirements.txt
   ```
4. Ejecuta:
   ```
   python app.py
   ```
5. Abre `http://127.0.0.1:5000/`

## Notas de seguridad y revisión
- **No subas** tu `.env` a GitHub. Este ZIP incluye `.env.example` solamente.
- Las contraseñas se almacenan con hash (werkzeug). 2FA usa `pyotp` (TOTP).
- Para producción: no uses `app.run(debug=True)`. Emplea Gunicorn/uwsgi, HTTPS y almacenamiento de secretos seguro.
- Mejoras recomendadas: confirmación por correo, reestablecer contraseña, protección CSRF (Flask-WTF), límites de intentos y logs de seguridad.
