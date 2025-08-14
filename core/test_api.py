import pytest
from django.urls import reverse
from django.contrib.auth.models import User
from core.models import Organization, Profile
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

@pytest.mark.django_db
def test_unauthenticated_access():
    """
    Tests that an unauthenticated user receives a 401 Unauthorized error.
    """
    client = APIClient()
    url = reverse('organization-list-create')
    response = client.get(url)
    assert response.status_code == 401

@pytest.mark.django_db
def test_admin_can_create_organization():
    """
    HAPPY PATH TEST:
    Tests that a logged-in admin user CAN create a new organization.
    """
    client = APIClient()
    # Arrange: Create an admin user
    admin_user = User.objects.create_user(username='testadmin', password='password123')
    Profile.objects.create(user=admin_user, role='admin')
    
    # Manually generate a token for the user
    refresh = RefreshToken.for_user(admin_user)
    # Add the token to the client's headers for all subsequent requests
    client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

    url = reverse('organization-list-create')
    data = {"name": "Test Company", "industry": "Testing", "registration_no": "TC-123"}

    # Act: Make the authenticated POST request
    response = client.post(url, data, format='json')

    # Assert: Check that the creation was successful
    assert response.status_code == 201
    assert Organization.objects.count() == 1
    assert Organization.objects.get().name == "Test Company"

@pytest.mark.django_db
def test_client_cannot_create_organization():
    """
    SAD PATH TEST:
    Tests that a logged-in non-admin user CANNOT create a new organization.
    """
    client = APIClient()
    # Arrange: Create a non-admin user
    client_user = User.objects.create_user(username='testclient', password='password123')
    Profile.objects.create(user=client_user, role='client')

    # Manually generate a token for this user
    refresh = RefreshToken.for_user(client_user)
    client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

    url = reverse('organization-list-create')
    data = {"name": "Another Company", "industry": "Intrusion", "registration_no": "AC-456"}

    # Act: Make the authenticated POST request
    response = client.post(url, data, format='json')

    # Assert: Check that the user was forbidden
    assert response.status_code == 403
    assert Organization.objects.count() == 0