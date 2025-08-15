# core/authentication.py
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model

User = get_user_model()

class CertificateAuthenticationBackend(BaseBackend):
    def authenticate(self, request):
        client_dn = request.headers.get('x-client-dn')
        if not client_dn:
            return None
        try:
            # Extracts the username from a certificate subject like /CN=testuser
            username = [part for part in client_dn.split('/') if part.startswith('CN=')][0].split('=')[1]
        except IndexError:
            return None

        try:
            user = User.objects.get(username=username)
            return user
        except User.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None