# core/models.py

from django.db import models
from django.contrib.auth.models import User #<-- Import User model
from django.utils import timezone
import uuid


# Add this new Profile model
class Profile(models.Model):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('auditor', 'Auditor'),
        ('client', 'Client'),
    )
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='client')
    mfa_secret = models.CharField(max_length=255, blank=True, null=True)
    mfa_enabled = models.BooleanField(default=False)


    def __str__(self):
        return f"{self.user.username}'s Profile"


# This class represents the Organizations Table from your PRD
class Organization(models.Model):
    name = models.CharField(max_length=200)
    industry = models.CharField(max_length=100)
    registration_no = models.CharField(max_length=50, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

# This class represents the Scans Table from your PRD
class Scan(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    # This creates a relationship. Each Scan belongs to one Organization.
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    scan_date = models.DateTimeField(default=timezone.now)
    compliance_score = models.FloatField(default=0.0)
    risk_level = models.CharField(max_length=20, default='Unknown')
    signed_report_path = models.CharField(max_length=255, blank=True)
    blockchain_hash = models.CharField(max_length=255, blank=True)
    digital_signature = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Scan for {self.organization.name} on {self.scan_date.strftime('%Y-%m-%d')}"
    

class ChecklistCategory(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.name

class ChecklistItem(models.Model):
    category = models.ForeignKey(ChecklistCategory, on_delete=models.CASCADE, related_name='items')
    name = models.CharField(max_length=255)
    description = models.TextField()
    weight = models.PositiveIntegerField(default=1, help_text="Weight for score calculation (e.g., 1-5)")

    def __str__(self):
        return self.name

class ScanResult(models.Model):
    STATUS_CHOICES = (
        ('pass', 'Pass'),
        ('fail', 'Fail'),
        ('na', 'Not Applicable'),
    )
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='results')
    checklist_item = models.ForeignKey(ChecklistItem, on_delete=models.CASCADE)
    status = models.CharField(max_length=4, choices=STATUS_CHOICES, default='na')
    notes = models.TextField(blank=True, help_text="Details about the finding or vulnerability.")

    def __str__(self):
        return f"{self.scan.organization.name} - {self.checklist_item.name}: {self.status}"


class AuditLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.TextField(blank=True, null=True)

    class Meta:
        ordering = ['-timestamp'] # Show the newest logs first

    def __str__(self):
        return f"{self.user.username if self.user else 'System'} - {self.action} at {self.timestamp.strftime('%Y-%m-%d %H:%M')}"





