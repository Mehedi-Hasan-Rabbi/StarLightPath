# Star Light Path

ciana project

---

Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Tech stack](#tech-stack)
- [Repository layout](#repository-layout)
- [Requirements](#requirements)
- [Quickstart (development)](#quickstart-development)
  - [1. Clone](#1-clone)
  - [2. Create virtual environment & install](#2-create-virtual-environment--install)
  - [3. Configure environment variables](#3-configure-environment-variables)
  - [4. Database migrations](#4-database-migrations)
  - [5. Create superuser](#5-create-superuser)
  - [6. Run development server](#6-run-development-server)
- [Working with static & media files](#working-with-static--media-files)
- [Redis / Cache](#redis--cache)
- [API documentation](#api-documentation)
- [Production / deployment notes](#production--deployment-notes)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License & contact](#license--contact)

---

Overview
--------
Star Light Path is a Django-based REST API project (internal name: "ciana project"). It provides API endpoints under `/api/` and includes JWT authentication, API schema generation and documentation (drf-spectacular), and support for Redis caching.

From repository files:
- Django project module: `starlightpath`
- Installed local apps: `user`, `application`, `program`
- API URL prefixes seen in `starlightpath/urls.py`:
  - `/api/auth/` — authentication / user endpoints
  - `/api/application/` — application app endpoints
  - `/api/program/` — program app endpoints
- API schema and docs:
  - `/api/schema/` (OpenAPI)
  - `/api/doc/` (Swagger UI)
  - `/api/redoc/` (ReDoc)

Tech stack
----------
- Python (recommended 3.10+ / 3.11)
- Django 6.0.1
- Django REST Framework
- drf-spectacular (OpenAPI schema + docs)
- djangorestframework-simplejwt (JWT authentication)
- django-cors-headers
- django-redis / redis
- whitenoise (static file serving)
- python-dotenv (for .env support)
See `requirements.txt` for full pinned package versions.

Repository layout (top-level)
-----------------------------
- manage.py
- requirements.txt
- .env.example
- starlightpath/
  - settings.py
  - urls.py
  - wsgi.py
- user/ (app)
- application/ (app)
- program/ (app)
- media/ (media files)
- staticfiles/ (recommended local static dir)

Requirements
------------
Install dependencies from `requirements.txt`. Example contents include:
- Django==6.0.1
- djangorestframework
- djangorestframework_simplejwt
- drf-spectacular
- django-redis
- python-dotenv
- whitenoise
(Use the provided `requirements.txt` file to install exact versions.)

Quickstart (development)
------------------------

1. Clone
```bash
git clone https://github.com/Mehedi-Hasan-Rabbi/StarLightPath.git
cd StarLightPath
```

2. Create virtual environment & install
```bash
python -m venv .venv
# macOS / Linux
source .venv/bin/activate
# Windows (PowerShell)
.venv\Scripts\Activate.ps1

pip install --upgrade pip
pip install -r requirements.txt
```

3. Configure environment variables
- Copy `.env.example` to `.env` and fill values:
```bash
cp .env.example .env
# then edit .env (SECRET_KEY, DEBUG, DB settings, REDIS_URL, EMAIL settings, etc.)
```
Important environment variables seen in `.env.example` and `settings.py`:
- SECRET_KEY, DEBUG, ALLOWED_HOSTS
- DB_ENGINE, DB_NAME, DB_USER, DB_PASSWORD, DB_HOST, DB_PORT
- REDIS_URL
- CORS_ALLOWED_ORIGINS
- EMAIL_BACKEND, EMAIL_HOST, EMAIL_PORT, EMAIL_USE_TLS, EMAIL_HOST_USER, EMAIL_HOST_PASSWORD
- SIMPLE_JWT_ACCESS_TOKEN_HOURS, SIMPLE_JWT_REFRESH_TOKEN_DAYS, SIMPLE_JWT_ROTATE_REFRESH_TOKENS, SIMPLE_JWT_BLACKLIST_AFTER_ROTATION
- MEDIA_ROOT / MEDIA_URL, AUTH_USER_MODEL (defaults to `user.Users`)

By default, settings use SQLite (DB_ENGINE=django.db.backends.sqlite3) and a file at `db.sqlite3`.

4. Database migrations
```bash
python manage.py migrate
```

5. Create superuser (for admin access)
```bash
python manage.py createsuperuser
```

6. Run development server
```bash
python manage.py runserver
# Visit http://127.0.0.1:8000/
# Admin: http://127.0.0.1:8000/admin/
# API docs: http://127.0.0.1:8000/api/doc/ or /api/redoc/
```

Working with static & media files
--------------------------------
- Development: static files are served automatically by Django when DEBUG=True.
- Production: run collectstatic and serve with whitenoise or via your web server:
```bash
python manage.py collectstatic --noinput
```
- MEDIA_ROOT is set from environment variable `MEDIA_ROOT` (default `./media` in .env.example). Ensure your web server or storage backend serves media files in production.

Redis / Cache
-------------
`settings.py` configures a Redis cache using `REDIS_URL`. If you want caching/session backing or celery (not included by default) use:
```
REDIS_URL=redis://127.0.0.1:6379/1
```
Install and run Redis locally or point to a managed Redis instance.

API documentation
-----------------
OpenAPI schema and automatic docs are available:
- Schema: GET /api/schema/
- Swagger UI: /api/doc/
- ReDoc: /api/redoc/

These endpoints are configured through `drf_spectacular` in `starlightpath/urls.py`.

Authentication
--------------
The project uses Simple JWT for authentication (configured in `REST_FRAMEWORK` and `SIMPLE_JWT` in settings). The exact auth endpoints depend on `user.urls` inside the `user` app. If standard simplejwt views are used, token endpoints might look like:
- POST /api/auth/token/ — obtain token pair
- POST /api/auth/token/refresh/ — refresh access token
Check `/api/doc/` or `/api/schema/` after starting the server to confirm exact paths and payloads.

Production / deployment notes
-----------------------------
- Set `DEBUG=False`, set a strong `SECRET_KEY`, and add your domain(s) to `ALLOWED_HOSTS`.
- Use PostgreSQL or other production-ready DB: set `DB_ENGINE=django.db.backends.postgresql` and fill DB_* variables.
- Configure email SMTP settings in `.env`.
- Use Gunicorn + whitenoise (or a web server like nginx) to serve static files in production. Example Gunicorn command:
```bash
gunicorn starlightpath.wsgi:application --workers 3 --bind 0.0.0.0:8000
```
- Ensure `SECURE_SSL_REDIRECT`, `CSRF_COOKIE_SECURE`, `SESSION_COOKIE_SECURE`, HSTS settings are configured in env for HTTPS.

Testing
-------
There are no tests included in the repository (if you don't see a `tests.py` or `tests/` directories in apps). To add tests, use Django's test framework:
```bash
python manage.py test
```

Troubleshooting
---------------
- "Couldn't import Django" — ensure you activated the virtualenv and installed requirements.
- Database errors — confirm DB_ENGINE and DB_* environment variables.
- Static/media not found — ensure `collectstatic` ran in production and MEDIA_ROOT is configured.

Contributing
------------
1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make changes & add tests
4. Open a PR describing your changes

If you plan to contribute, please add a short PR description and link any issue it resolves.

License & contact
-----------------
- No LICENSE file detected in the repository. If you want others to use or contribute to this project, add a license (for example: MIT, Apache-2.0).
- Repo: https://github.com/Mehedi-Hasan-Rabbi/StarLightPath
- Maintainer: Mehedi-Hasan-Rabbi

Additional notes
----------------
- I inspected `manage.py`, `starlightpath/settings.py`, `starlightpath/urls.py`, `requirements.txt`, and `.env.example` to build this README. There may be more app-specific details inside `user`, `application`, and `program` application folders that you should document (models, serializers, API endpoints). Start the server and visit `/api/doc/` or `/api/schema/` for the most accurate, auto-generated API docs for your current codebase.
