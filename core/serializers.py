# core/serializers.py
from rest_framework import serializers
from .models import Organization, Scan, ChecklistItem, ScanResult, Profile, AuditLog
from django.contrib.auth.models import User

class AuditLogSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    class Meta:
        model = AuditLog
        fields = ['id', 'timestamp', 'username', 'action', 'details']

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['role']

class UserSerializer(serializers.ModelSerializer):
    profile = ProfileSerializer()
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'profile', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        profile_data = validated_data.pop('profile')
        password = validated_data.pop('password')
        user = User.objects.create(**validated_data)
        user.set_password(password)
        user.save()
        Profile.objects.create(user=user, **profile_data)
        return user

    def update(self, instance, validated_data):
        if 'profile' in validated_data:
            profile_data = validated_data.pop('profile')
            profile = instance.profile
            profile.role = profile_data.get('role', profile.role)
            profile.save()
        if 'password' in validated_data:
            password = validated_data.pop('password')
            instance.set_password(password)
        return super().update(instance, validated_data)

class ScanResultSerializer(serializers.ModelSerializer):
    checklist_item_name = serializers.CharField(source='checklist_item.name', read_only=True)
    class Meta:
        model = ScanResult
        # This fields list is now correct and does not include 'uuid'
        fields = ['id', 'checklist_item_name', 'status', 'notes']

class ScanSerializer(serializers.ModelSerializer):
    results = ScanResultSerializer(many=True, read_only=True)
    class Meta:
        model = Scan
        # This fields list correctly includes 'uuid' because the Scan model has it
        fields = ['id', 'uuid', 'scan_date', 'compliance_score', 'risk_level', 'results']

class OrganizationSerializer(serializers.ModelSerializer):
    scans = ScanSerializer(many=True, read_only=True, source='scan_set')
    latest_scan_score = serializers.SerializerMethodField()
    latest_scan_risk = serializers.SerializerMethodField()

    class Meta:
        model = Organization
        fields = [
            'id', 'name', 'industry', 'registration_no', 'created_at', 
            'scans', 'latest_scan_score', 'latest_scan_risk'
        ]

    def get_latest_scan_score(self, obj):
        latest_scan = obj.scan_set.order_by('-scan_date').first()
        return latest_scan.compliance_score if latest_scan else None

    def get_latest_scan_risk(self, obj):
        latest_scan = obj.scan_set.order_by('-scan_date').first()
        return latest_scan.risk_level if latest_scan else "Not Scanned"