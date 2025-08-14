# core/urls.py

from django.urls import path, include
from .views import OrganizationListCreateView, CreateScanView, OrganizationDetailView
from rest_framework.routers import DefaultRouter # 
from .views import GenerateReportPDFView # <-- Import our new view
from .views import VerifyReportView, UserViewSet
from .views import MFASetupView # <-- Import the new view
from .views import AuditLogViewSet


# Create a router and register our viewsets with it.
router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'auditlogs', AuditLogViewSet, basename='auditlog')

urlpatterns = [
    path('', include(router.urls)),
    path('organizations/', OrganizationListCreateView.as_view(), name='organization-list-create'),
    path('organizations/<int:pk>/', OrganizationDetailView.as_view(), name='organization-detail'),
    path('scans/create/', CreateScanView.as_view(), name='scan-create'),
    path('scans/<uuid:scan_uuid>/report/', GenerateReportPDFView.as_view(), name='scan-report-pdf'),
    path('scans/verify/', VerifyReportView.as_view(), name='scan-verify'),
    path('mfa/setup/', MFASetupView.as_view(), name='mfa-setup'),
]