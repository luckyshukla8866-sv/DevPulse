from rest_framework import serializers
from .models import ActivityLog
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.exceptions import AuthenticationFailed

class ActivityLogSerializer(serializers.ModelSerializer):
    
    integration_name=serializers.CharField(source='integration.name',read_only=True)
    created_at = serializers.DateTimeField(format="%Y-%m-%d, %H:%M:%S", read_only=True)

    class Meta:
        model=ActivityLog
        fields=[
            "id",
            "integration_name",
            "event_type",
            "severity",
            "created_at"
        ]

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):

    def validate(self, attrs):
        try:
            data = super().validate(attrs)
            print("data:",data)
            return data

        except AuthenticationFailed:
            raise AuthenticationFailed({
                "status": "failed",
                "message": "Invalid email or password"
            })