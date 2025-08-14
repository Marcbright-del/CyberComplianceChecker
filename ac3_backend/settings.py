import os
import dj_database_url
from pathlib import Path
from dotenv import load_dotenv # <-- Add this import
load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
# Heroku will provide this value. We use a default for local development.
SECRET_KEY = os.environ.get(
    'SECRET_KEY', 
    'django-insecure-YOUR-DEFAULT-KEY-HERE' # Replace with your original key
)

# SECURITY WARNING: don't run with debug turned on in production!
# We set DEBUG to False on Heroku, and True locally.
DEBUG = os.environ.get('DEBUG', 'True') == 'True'

ALLOWED_HOSTS = [
     # This gets the live URL from Render's environment
    os.environ.get('RENDER_EXTERNAL_HOSTNAME', None),
    # Add these for local development
    'localhost',
    '127.0.0.1',
]
ALLOWED_HOSTS = [host for host in ALLOWED_HOSTS if host]
# We will add our Heroku app URL here later.
# For now, we get it from an environment variable if it exists.
RENDER_EXTERNAL_HOSTNAME = os.environ.get('RENDER_EXTERNAL_HOSTNAME')
if RENDER_EXTERNAL_HOSTNAME:
    ALLOWED_HOSTS.append(RENDER_EXTERNAL_HOSTNAME)

# Application definition
INSTALLED_APPS = [
    
    
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django_otp',
    'django_otp.plugins.otp_totp',
    'django.contrib.messages',
    'whitenoise.runserver_nostatic', # For static files
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
    'core.apps.CoreConfig',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware', # For static files
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django_otp.middleware.OTPMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'ac3_backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'ac3_backend.wsgi.application'
ASGI_APPLICATION = 'ac3_backend.asgi.application'

# Database Configuration for Heroku
DATABASES = {
    'default': dj_database_url.config(
        # Fallback to SQLite for local development
        default=f'sqlite:///{BASE_DIR / "db.sqlite3"}',
        conn_max_age=600
    )
}

# ... (Your AUTH_PASSWORD_VALIDATORS, etc. can remain the same) ...

# Internationalization, Language, Timezone settings...

# Static files (CSS, JavaScript, Images)
STATIC_URL = 'static/'
# This is where Django will collect all static files for production
STATIC_ROOT = BASE_DIR / 'staticfiles' 
# Tell WhiteNoise where to find files and to use compression
STORAGES = {
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# --- Keep all your other custom settings below ---
AUTHENTICATION_BACKENDS = [
    'core.authentication.CertificateAuthenticationBackend',
    'django.contrib.auth.backends.ModelBackend',
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    )
}

# This will read the comma-separated list from your Render environment variable
CORS_ALLOWED_ORIGINS = os.environ.get('CORS_ALLOWED_ORIGINS', 'http://localhost:5173').split(',')

CSRF_TRUSTED_ORIGINS = os.environ.get('CSRF_TRUSTED_ORIGINS', 'http://localhost:5173').split(',')
# We will add our live frontend URL to this list later


SCANNER_API_KEY = os.environ.get('SCANNER_API_KEY', 'YOUR_API_KEY_GOES_HERE')