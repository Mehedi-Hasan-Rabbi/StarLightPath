# Star Light Path 🌟

A Django REST Framework API for managing housing applications and programs with a sophisticated role-based permission system.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Setup Steps](#setup-steps)
- [Configuration](#configuration)
- [API Endpoints](#api-endpoints)
  - [Authentication Endpoints](#authentication-endpoints)
  - [User Management](#user-management)
  - [Application Endpoints](#application-endpoints)
  - [Program Endpoints](#program-endpoints)
- [Role-Based Permissions](#role-based-permissions)
- [OTP Password Reset System](#otp-password-reset-system)
- [Running the Project](#running-the-project)
- [Testing](#testing)
- [Deployment](#deployment)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

Star Light Path is a comprehensive Django REST API project designed to manage housing applications and programs. The system features a three-tier role system (USER/ADMIN/SUPERUSER) with JWT authentication, Redis-powered OTP password reset, and automatic API documentation.

**Key Components:**
- **User App**: Custom user model with role-based permissions, JWT authentication, and OTP password reset
- **Application App**: Pre-screen housing applications with multi-step form data (APPLY/REFER types)
- **Program App**: Program catalog with nested sections (public + admin endpoints)

---

## Features

✨ **Core Features:**
- JWT-based authentication with token refresh and blacklisting
- Three-tier role system (USER, ADMIN, SUPERUSER) with granular permissions
- Stateless OTP password reset system using Redis
- Custom user model using email as primary identifier
- Multi-step housing application forms with conditional validation
- Program management with nested sections
- Automatic email notifications to superusers on new applications
- Built-in API documentation (Swagger UI & ReDoc)
- CORS support for frontend integration
- Media file handling for user images and program assets

---

## Technology Stack

### Backend Framework
- **Django 6.0.1** - High-level Python web framework
- **Django REST Framework 3.16.1** - Powerful toolkit for building Web APIs
- **Python 3.10+** - Programming language

### Authentication & Security
- **djangorestframework-simplejwt 5.5.1** - JWT authentication
- **PyJWT 2.10.1** - JSON Web Token implementation
- **django-cors-headers 4.9.0** - CORS handling

### Database & Caching
- **SQLite** (development) / **PostgreSQL** (production recommended)
- **Redis 7.1.0** - In-memory data store for caching and OTP storage
- **django-redis 6.0.0** - Redis cache backend for Django
- **hiredis 3.3.0** - High-performance Redis protocol parser

### API Documentation
- **drf-spectacular 0.29.0** - OpenAPI 3.0 schema generation
- **uritemplate 4.2.0** - URI template parsing

### Additional Tools
- **Pillow 12.1.0** - Image processing library
- **python-dotenv 1.2.1** - Environment variable management
- **whitenoise 6.11.0** - Static file serving
- **PyYAML 6.0.3** - YAML parser

### Complete Dependencies
See [requirements.txt](requirements.txt) for the full list of pinned package versions.

---

## Project Structure

```
StarLightPath/
├── manage.py                 # Django management script
├── requirements.txt          # Python dependencies
├── db.sqlite3               # SQLite database (development)
├── README.md                # Project documentation
│
├── starlightpath/           # Main project configuration
│   ├── __init__.py
│   ├── settings.py          # Django settings with env configuration
│   ├── urls.py              # Root URL configuration
│   ├── wsgi.py              # WSGI application entry point
│   └── asgi.py              # ASGI application entry point
│
├── user/                    # User management app
│   ├── models.py            # Custom User model with roles
│   ├── views.py             # Auth, admin management, password reset views
│   ├── serializers.py       # User serializers
│   ├── permissions.py       # Role-based permissions
│   ├── urls.py              # User app URL patterns
│   ├── utils.py             # OTP generation and validation utilities
│   ├── admin.py             # Django admin configuration
│   └── migrations/          # Database migrations
│
├── application/             # Housing application management
│   ├── models.py            # Application model with conditional fields
│   ├── views.py             # Application CRUD views
│   ├── serializers.py       # Application serializers
│   ├── paginations.py       # Custom pagination classes
│   ├── urls.py              # Application URL patterns
│   └── migrations/          # Database migrations
│
├── program/                 # Program catalog management
│   ├── models.py            # Program and ProgramSection models
│   ├── views.py             # Program ViewSets and public views
│   ├── serializers.py       # Program serializers (read/write)
│   ├── permissions.py       # Program-specific permissions
│   ├── urls.py              # Program URL patterns (REST router)
│   └── migrations/          # Database migrations
│
└── media/                   # User-uploaded files
    ├── user_images/         # User profile images
    └── programs/            # Program-related media
        ├── feature_images/  # Program feature images
        └── sections/        # Section images
```

---

## Installation

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)
- Redis server (for OTP and caching)
- Virtual environment tool (venv, virtualenv, or conda)
- Git

### Setup Steps

#### 1. Clone the Repository

```bash
git clone https://github.com/Mehedi-Hasan-Rabbi/StarLightPath.git
cd StarLightPath
```

#### 2. Create and Activate Virtual Environment

**Windows (PowerShell):**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**macOS/Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

#### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

#### 4. Configure Environment Variables

Create a `.env` file in the project root:

```bash
# Windows
copy .env.example .env

# macOS/Linux
cp .env.example .env
```

Edit `.env` with your configuration (see [Configuration](#configuration) section).

#### 5. Install and Start Redis

**Windows:**
- Download Redis for Windows or use Docker
- Or use WSL: `sudo service redis-server start`

**macOS:**
```bash
brew install redis
brew services start redis
```

**Linux:**
```bash
sudo apt-get install redis-server
sudo systemctl start redis
```

#### 6. Run Database Migrations

```bash
python manage.py migrate
```

#### 7. Create Superuser

```bash
python manage.py createsuperuser
```

Follow the prompts to enter:
- Email address
- Full name
- Password

#### 8. Run Development Server

```bash
python manage.py runserver
```

The API will be available at:
- **API Root**: http://127.0.0.1:8000/api/
- **Admin Panel**: http://127.0.0.1:8000/admin/
- **Swagger UI**: http://127.0.0.1:8000/api/doc/
- **ReDoc**: http://127.0.0.1:8000/api/redoc/
- **API Schema**: http://127.0.0.1:8000/api/schema/

---

## Configuration

### Environment Variables

Create a `.env` file in the project root with the following variables:

#### Core Settings
```env
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=127.0.0.1,localhost
```

#### Database (SQLite - Default)
```env
DB_ENGINE=django.db.backends.sqlite3
DB_NAME=db.sqlite3
```

#### Database (PostgreSQL - Production)
```env
DB_ENGINE=django.db.backends.postgresql
DB_NAME=starlightpath
DB_USER=postgres
DB_PASSWORD=yourpassword
DB_HOST=localhost
DB_PORT=5432
```

#### Redis Configuration
```env
REDIS_URL=redis://127.0.0.1:6379/1
```

#### CORS Settings
```env
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
```

#### JWT Settings
```env
SIMPLE_JWT_ACCESS_TOKEN_HOURS=1
SIMPLE_JWT_REFRESH_TOKEN_DAYS=7
SIMPLE_JWT_ROTATE_REFRESH_TOKENS=True
SIMPLE_JWT_BLACKLIST_AFTER_ROTATION=True
```

#### Email Configuration (SMTP)
```env
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
DEFAULT_FROM_EMAIL=your-email@gmail.com
```

#### OTP Password Reset Settings
```env
PASSWORD_RESET_OTP_TTL=600                    # 10 minutes
PASSWORD_RESET_OTP_LENGTH=5
PASSWORD_RESET_MAX_REQUESTS_PER_HOUR=5
PASSWORD_RESET_MAX_VERIFY_ATTEMPTS=5
PASSWORD_RESET_RESEND_COOLDOWN=60             # 60 seconds
PASSWORD_RESET_VERIFIED_TTL=600               # 10 minutes
PASSWORD_RESET_OTP_PEPPER=your-secret-pepper
```

#### Media Files
```env
MEDIA_URL=/media/
MEDIA_ROOT=./media
```

---

## API Endpoints

### Authentication Endpoints

| Method | Endpoint | Permission | Description |
|--------|----------|-----------|-------------|
| POST | `/api/auth/login/` | AllowAny | Login with email/password, returns JWT tokens |
| POST | `/api/auth/logout/` | IsAuthenticated | Logout and blacklist refresh token |
| POST | `/api/auth/token/refresh/` | AllowAny | Refresh access token using refresh token |
| POST | `/api/auth/token/verify/` | AllowAny | Verify JWT token validity |

#### Password Reset Flow (OTP-based)

| Method | Endpoint | Permission | Description |
|--------|----------|-----------|-------------|
| POST | `/api/auth/password/forgot/` | AllowAny | Request OTP for password reset |
| POST | `/api/auth/password/verify/` | AllowAny | Verify OTP code |
| POST | `/api/auth/password/reset/` | AllowAny | Reset password after OTP verification |

### User Management

#### Current User

| Method | Endpoint | Permission | Description |
|--------|----------|-----------|-------------|
| GET | `/api/auth/me/` | IsAuthenticated | Get current user profile |
| PUT/PATCH | `/api/auth/me/update/` | IsAuthenticated | Update current user profile |
| POST | `/api/auth/change-password/` | IsAuthenticated | Change password for logged-in user |

#### Admin Management (Superuser Only)

| Method | Endpoint | Permission | Description |
|--------|----------|-----------|-------------|
| GET | `/api/auth/admins/` | IsAdminOrSuperUser | List all admin users |
| POST | `/api/auth/admins/create/` | IsSuperUser | Create new admin user |
| GET | `/api/auth/admins/{id}/` | IsAdminOrSuperUser | Get admin user details |
| PUT/PATCH | `/api/auth/admins/{id}/update/` | IsSuperUser | Update admin user |
| DELETE | `/api/auth/admins/{id}/delete/` | IsSuperUser | Delete admin user |

#### Dashboard

| Method | Endpoint | Permission | Description |
|--------|----------|-----------|-------------|
| GET | `/api/auth/dashboard/summary/` | IsAdminOrSuperUser | Get dashboard summary statistics |
| GET | `/api/auth/dashboard/applications/monthly/` | IsAdminOrSuperUser | Get monthly application statistics |

### Application Endpoints

| Method | Endpoint | Permission | Description |
|--------|----------|-----------|-------------|
| POST | `/api/application/new/` | AllowAny | Create new housing application (public) |
| GET | `/api/application/list/` | IsAdminOrSuperUser | List all applications (paginated) |
| GET | `/api/application/{id}/` | IsAdminOrSuperUser | Get application details |

**Note**: The create endpoint is public to allow applicants to submit without authentication. Email notifications are sent to superusers on new submissions.

### Program Endpoints

#### Admin Program Management (ViewSet)

| Method | Endpoint | Permission | Description |
|--------|----------|-----------|-------------|
| GET | `/api/program/programs/` | IsAdminOrSuperUser | List all programs |
| POST | `/api/program/programs/` | IsSuperUser | Create new program |
| GET | `/api/program/programs/{id}/` | IsAdminOrSuperUser | Get program details |
| PUT/PATCH | `/api/program/programs/{id}/` | IsSuperUser | Update program |
| DELETE | `/api/program/programs/{id}/` | IsSuperUser | Delete program |

#### Program Section Management (ViewSet)

| Method | Endpoint | Permission | Description |
|--------|----------|-----------|-------------|
| GET | `/api/program/program-sections/` | IsAdminOrSuperUser | List all program sections |
| POST | `/api/program/program-sections/` | IsSuperUser | Create new section |
| GET | `/api/program/program-sections/{id}/` | IsAdminOrSuperUser | Get section details |
| PUT/PATCH | `/api/program/program-sections/{id}/` | IsSuperUser | Update section |
| DELETE | `/api/program/program-sections/{id}/` | IsSuperUser | Delete section |

#### Public Program Endpoints

| Method | Endpoint | Permission | Description |
|--------|----------|-----------|-------------|
| GET | `/api/program/public/` | AllowAny | List all programs (public access) |
| GET | `/api/program/public/{id}/` | AllowAny | Get program details with sections (public) |

---

## Role-Based Permissions

The system implements a three-tier role-based permission system:

### User Roles

1. **USER** (`role='USER'`)
   - Default role for registered users
   - Can submit housing applications (public endpoint)
   - Limited to their own profile

2. **ADMIN** (`role='ADMIN'`, `is_staff=True`, `is_superuser=False`)
   - Read-only access to applications and programs
   - Can view dashboard statistics
   - Cannot create/update/delete programs or manage other admins

3. **SUPERUSER** (`role='SUPERUSER'`, `is_staff=True`, `is_superuser=True`)
   - Full system access
   - Can create/update/delete programs and sections
   - Can manage admin users (CRUD operations)
   - Receives email notifications for new applications

### Permission Classes

- `IsSuperUser` - Only superusers
- `IsAdminOrSuperUser` - Admins and superusers
- `IsAdminUser` - Only admin users (not superusers)
- `IsSuperUserOrAdminReadOnly` - Superusers (full access) + Admins (read-only)

### Custom User Model

The project uses **email** as the primary authentication field (not username):

```python
# User creation
python manage.py createsuperuser  # Creates SUPERUSER
# OR via API
POST /api/auth/admins/create/  # Creates ADMIN (requires superuser auth)
```

---

## OTP Password Reset System

The project implements a stateless OTP (One-Time Password) password reset system using Redis for secure password recovery.

### Flow Overview

1. **Request OTP** → User provides email
2. **Verify OTP** → User enters OTP code from email
3. **Reset Password** → User sets new password

### Features

- **Rate Limiting**: Max 5 requests per hour per email
- **Cooldown Period**: 60 seconds between OTP requests
- **Attempt Limiting**: Max 5 verification attempts
- **Time-based Expiry**: OTP valid for 10 minutes
- **Verification Window**: 10 minutes to reset password after OTP verification
- **Hashed Storage**: OTPs stored as hashes (with pepper) in Redis

### Endpoints

```bash
# Step 1: Request OTP
POST /api/auth/password/forgot/
{
  "email": "user@example.com"
}

# Step 2: Verify OTP
POST /api/auth/password/verify/
{
  "email": "user@example.com",
  "otp": "12345"
}

# Step 3: Reset Password
POST /api/auth/password/reset/
{
  "email": "user@example.com",
  "password": "newpassword123",
  "password_confirm": "newpassword123"
}
```

### Redis Keys

The system uses the following Redis keys:

- `pwd-reset:otp:{email}` - Hashed OTP
- `pwd-reset:verified:{email}` - Verification status
- `pwd-reset:reqcount:{email}` - Request count
- `pwd-reset:attempts:{email}` - Verification attempts

---

## Running the Project

### Development Server

```bash
# Activate virtual environment
# Windows PowerShell
.venv\Scripts\Activate.ps1

# macOS/Linux
source .venv/bin/activate

# Start Redis (if not running)
redis-server

# Run Django development server
python manage.py runserver
```

### Running Migrations

```bash
# Create new migrations after model changes
python manage.py makemigrations

# Apply migrations
python manage.py migrate
```

### Creating Users

```bash
# Create superuser via CLI
python manage.py createsuperuser

# Create admin via API (requires superuser authentication)
POST /api/auth/admins/create/
```

### Collecting Static Files

```bash
python manage.py collectstatic --noinput
```

---

## Testing

Currently, no test suite is implemented. To add tests:

### Running Tests

```bash
python manage.py test
```

### Test Structure

Create test files in each app:

```
user/
  tests/
    __init__.py
    test_models.py
    test_views.py
    test_permissions.py
```

### Example Test

```python
from django.test import TestCase
from rest_framework.test import APITestCase
from rest_framework import status

class LoginViewTests(APITestCase):
    def test_login_success(self):
        # Test login with valid credentials
        response = self.client.post('/api/auth/login/', {
            'email': 'test@example.com',
            'password': 'testpass123'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
```

---

## Deployment

### Production Checklist

- [ ] Set `DEBUG=False` in `.env`
- [ ] Configure strong `SECRET_KEY`
- [ ] Set `ALLOWED_HOSTS` to your domain
- [ ] Use PostgreSQL database
- [ ] Configure Redis for production
- [ ] Set up SMTP email service
- [ ] Enable HTTPS and security headers
- [ ] Run `collectstatic` for static files
- [ ] Set up media file storage (S3, etc.)
- [ ] Configure logging
- [ ] Set up monitoring and error tracking

### Environment Variables (Production)

```env
DEBUG=False
SECRET_KEY=your-production-secret-key
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com

# Database
DB_ENGINE=django.db.backends.postgresql
DB_NAME=starlightpath_prod
DB_USER=produser
DB_PASSWORD=strongpassword
DB_HOST=your-db-host.com
DB_PORT=5432

# Security
SECURE_SSL_REDIRECT=True
CSRF_COOKIE_SECURE=True
SESSION_COOKIE_SECURE=True
SECURE_HSTS_SECONDS=31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS=True
SECURE_HSTS_PRELOAD=True
```

### Using Gunicorn

```bash
# Install Gunicorn
pip install gunicorn

# Run with Gunicorn
gunicorn starlightpath.wsgi:application --workers 3 --bind 0.0.0.0:8000
```

### Using Docker (Optional)

Create a `Dockerfile`:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python manage.py collectstatic --noinput
CMD ["gunicorn", "starlightpath.wsgi:application", "--bind", "0.0.0.0:8000"]
```

---

## Contributing

We welcome contributions! Please follow these guidelines:

### How to Contribute

1. **Fork the repository**
   ```bash
   git clone https://github.com/Mehedi-Hasan-Rabbi/StarLightPath.git
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feat/your-feature-name
   ```

3. **Make your changes**
   - Follow PEP 8 style guidelines
   - Add tests for new features
   - Update documentation

4. **Commit your changes**
   ```bash
   git commit -m "Add: description of your feature"
   ```

5. **Push to your fork**
   ```bash
   git push origin feat/your-feature-name
   ```

6. **Open a Pull Request**
   - Provide a clear description
   - Link related issues
   - Ensure CI passes

### Coding Standards

- Follow Django and DRF best practices
- Use type hints where applicable
- Write descriptive commit messages
- Add docstrings to functions and classes
- Keep functions small and focused

### Commit Message Format

```
Type: Short description

Longer description if needed

Types: Add, Update, Fix, Remove, Refactor, Docs, Test
```

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

- **Repository**: [https://github.com/Mehedi-Hasan-Rabbi/StarLightPath](https://github.com/Mehedi-Hasan-Rabbi/StarLightPath)
- **Maintainer**: Mehedi Hasan Rabbi

---

Made with ❤️ by Mehedi Hasan Rabbi