release: python manage.py migrate
web: gunicorn ac3_backend.wsgi --log-file -
worker: celery -A ac3_backend worker -l info -P gevent