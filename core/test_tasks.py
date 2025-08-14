# core/test_tasks.py
import pytest
from django.contrib.auth.models import User
from .models import Organization, Profile, ChecklistCategory, ChecklistItem, Scan
from .tasks import run_scan_task

@pytest.fixture
def setup_checklist_data():
    """A pytest fixture to create necessary data for a scan test."""
    # Create a user and organization
    user = User.objects.create_user(username='testuser', password='password')
    Profile.objects.create(user=user, role='admin')
    org = Organization.objects.create(name="Test Org", industry="IT", registration_no="TO-001")

    # Create checklist items with specific weights
    category = ChecklistCategory.objects.create(name="Test Category")
    ChecklistItem.objects.create(category=category, name="Critical Item", description="...", weight=5)
    ChecklistItem.objects.create(category=category, name="Medium Item", description="...", weight=3)
    ChecklistItem.objects.create(category=category, name="Low Item", description="...", weight=2)

    return user, org

@pytest.mark.django_db
def test_scan_task_score_calculation(setup_checklist_data, mocker):
    """
    Tests that the weighted score calculation in the scan task is correct.
    """
    # Arrange: Get the user and org from our fixture
    user, org = setup_checklist_data

    # Mock the random.choice function to return a predictable sequence.
    # It will return 'pass' the first time it's called, then 'fail', then 'pass'.
    mocker.patch('random.choice', side_effect=['pass', 'fail', 'pass'])

    # Act: Run the task directly as a function
    run_scan_task(organization_id=org.id, user_id=user.id)

    # Assert: Check the results in the database
    assert Scan.objects.count() == 1
    scan = Scan.objects.first()

    # The items with weights 5 and 2 should have passed. The item with weight 3 failed.
    # Total possible score = 5 + 3 + 2 = 10
    # Achieved score = 5 (pass) + 0 (fail) + 2 (pass) = 7
    # Expected final score = (7 / 10) * 100 = 70.0
    expected_score = 70.0

    assert scan.compliance_score == expected_score
    assert scan.risk_level == "Medium" # 70 is in the "Medium" range