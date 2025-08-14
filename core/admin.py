# core/admin.py

from django.contrib import admin
from .models import Organization, Scan, Profile, ChecklistCategory, ChecklistItem, ScanResult, AuditLog

# Register your models here.
admin.site.register(Organization)
admin.site.register(Scan)
admin.site.register(Profile)

 #<-- Register Profile

admin.site.register(ChecklistCategory)
admin.site.register(ChecklistItem)
admin.site.register(ScanResult)
admin.site.register(AuditLog)