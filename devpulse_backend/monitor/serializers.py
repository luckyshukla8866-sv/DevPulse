from rest_framework import serializers
from .models import ActivityLog

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
