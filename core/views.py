import random
import hashlib
import base64
import os
import qrcode
import qrcode.image.svg
from io import BytesIO
import pyotp

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.core.signing import TimestampSigner, BadSignature, SignatureExpired
from django.http import HttpResponse
from django.template.loader import render_to_string

from rest_framework import generics, status, viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from .models import AuditLog
from .serializers import AuditLogSerializer

from weasyprint import HTML
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from rest_framework.parsers import MultiPartParser, FormParser

from .models import Scan, Organization
from .serializers import OrganizationSerializer, ScanSerializer, UserSerializer
from .permissions import IsAdminUser

from .scanner import CloudScanner # Make sure CloudScanner is imported


User = get_user_model()
signer = TimestampSigner()

# --- Authentication Views ---

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    refresh['username'] = user.username
    try:
        refresh['role'] = user.profile.role
    except user.profile.RelatedObjectDoesNotExist:
        refresh['role'] = 'client'
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class LoginStep1View(APIView):
    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)

        if user is None:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        if hasattr(user, 'profile') and user.profile.mfa_enabled:
            temp_token = signer.sign(str(user.id))
            return Response({"mfa_required": True, "temp_token": temp_token})
        else:
            tokens = get_tokens_for_user(user)
            return Response(tokens)

class LoginStep2View(APIView):
    def post(self, request, *args, **kwargs):
        temp_token = request.data.get('temp_token')
        otp_code = request.data.get('otp_code')

        if not temp_token or not otp_code:
            return Response({"error": "Missing token or OTP code"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user_id = signer.unsign(temp_token, max_age=120)
            user = User.objects.get(id=user_id)
            
            totp = pyotp.TOTP(user.profile.mfa_secret)
            if totp.verify(otp_code):
                tokens = get_tokens_for_user(user)
                return Response(tokens)
            else:
                return Response({"error": "Invalid OTP code"}, status=status.HTTP_400_BAD_REQUEST)

        except SignatureExpired:
            return Response({"error": "Login session expired, please try again."}, status=status.HTTP_400_BAD_REQUEST)
        except (BadSignature, User.DoesNotExist):
            return Response({"error": "Invalid request."}, status=status.HTTP_400_BAD_REQUEST)


# --- Organization and Scan Views ---

class OrganizationListCreateView(generics.ListCreateAPIView):
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer

    def get_permissions(self):
        if self.request.method == 'POST':
            return [IsAdminUser()]
        return [IsAuthenticated()]
    
    def perform_create(self, serializer):
        # First, save the new organization as usual
        organization = serializer.save()

        # Now, create the audit log entry for this action
        AuditLog.objects.create(
            user=self.request.user,
            action=f"Created new organization: '{organization.name}'",
            details=f"ID: {organization.id}, Industry: {organization.industry}"
        )

class OrganizationDetailView(generics.RetrieveAPIView):
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer
    lookup_field = 'pk'

class CreateScanView(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request, *args, **kwargs):
        org_id = request.data.get('organization_id')
        if not org_id:
            return Response({"error": "Organization ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            organization = Organization.objects.get(id=org_id)
        except Organization.DoesNotExist:
            return Response({"error": "Organization not found"}, status=status.HTTP_404_NOT_FOUND)

        # This is the change: We run the scan directly here
        print(f"Starting synchronous scan for {organization.name}")
        scanner = CloudScanner()
        # In a real app, the Organization model would have an IP/domain field
        target_ip = f"192.168.1.{organization.id}" 
        scan_result = scanner.run_scan(target_ip=target_ip)

        scan = Scan.objects.create(
            organization=organization,
            compliance_score=scan_result["score"],
            risk_level=scan_result["risk"]
        )

        print(f"Finished scan for {organization.name}")

        # Return the final score directly to the frontend
        return Response(
            {"message": "Scan completed successfully", "scan_id": scan.id, "score": scan.compliance_score},
            status=status.HTTP_201_CREATED
        )

# --- User and Profile Management Views ---

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer
    permission_classes = [IsAdminUser]

class MFASetupView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user
        secret = pyotp.random_base32()
        user.profile.mfa_secret = secret
        user.profile.save()

        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user.username,
            issuer_name="AC3 Platform"
        )

        image_factory = qrcode.image.svg.SvgPathImage
        qr_code_image = qrcode.make(provisioning_uri, image_factory=image_factory)
        
        stream = BytesIO()
        qr_code_image.save(stream)
        
        return Response({
            'qr_code_svg': stream.getvalue().decode('utf-8'),
            'provisioning_uri': provisioning_uri
        })

    def post(self, request, *args, **kwargs):
        user = request.user
        otp_code = request.data.get('otp_code')

        if not otp_code:
            return Response({"error": "OTP code is required."}, status=status.HTTP_400_BAD_REQUEST)

        totp = pyotp.TOTP(user.profile.mfa_secret)
        if totp.verify(otp_code):
            user.profile.mfa_enabled = True
            user.profile.save()
            return Response({"message": "MFA has been successfully enabled."})
        else:
            return Response({"error": "Invalid OTP code."}, status=status.HTTP_400_BAD_REQUEST)

# --- Report and Verification Views ---

class GenerateReportPDFView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, scan_uuid, *args, **kwargs):
        try:
            scan = Scan.objects.get(uuid=scan_uuid)
            organization = scan.organization
        except Scan.DoesNotExist:
            return Response({"error": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)

        context = {'scan': scan, 'organization': organization}
        html_string = render_to_string('core/report_template.html', context)
        pdf_file = HTML(string=html_string).write_pdf()

        pdf_hash = hashlib.sha256(pdf_file).digest()
        key_path = os.path.join(settings.BASE_DIR, 'private_key.pem')
        with open(key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
        signature = private_key.sign(
            pdf_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        scan.digital_signature = base64.b64encode(signature).decode('utf-8')
        scan.save()
        
        response = HttpResponse(pdf_file, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="compliance_report_{organization.name}_{scan.id}.pdf"'
        
        return response

class VerifyReportView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request, *args, **kwargs):
        scan_id = request.data.get('scan_id')
        uploaded_file = request.FILES.get('report')

        if not scan_id or not uploaded_file:
            return Response({"error": "Scan ID and report file are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            scan = Scan.objects.get(id=scan_id)
        except Scan.DoesNotExist:
            return Response({"verified": False, "reason": "Scan ID not found."}, status=status.HTTP_404_NOT_FOUND)

        if not scan.digital_signature:
            return Response({"verified": False, "reason": "No signature found for this scan."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            pdf_content = uploaded_file.read()
            uploaded_hash = hashlib.sha256(pdf_content).digest()

            key_path = os.path.join(settings.BASE_DIR, 'public_key.pem')
            with open(key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(key_file.read())

            stored_signature = base64.b64decode(scan.digital_signature)

            public_key.verify(
                stored_signature,
                uploaded_hash,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            return Response({"verified": True, "reason": "Signature is valid. Report is authentic."})

        except InvalidSignature:
            return Response({"verified": False, "reason": "Invalid signature. Report may have been altered."})
        except Exception as e:
            return Response({"verified": False, "reason": f"An unexpected error occurred: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint to view audit logs.
    Only accessible by Admins.
    """
    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializer
    permission_classes = [IsAdminUser] # Only Admins can view the audit trail







