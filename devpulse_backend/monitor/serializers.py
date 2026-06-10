from rest_framework import serializers
from .models import ActivityLog

class ActiivityLogSerializer(serializers.ModelSerializer):
    
    integration_name=serializers.CharField(source='integration.name',read_only=True)

    class Meta:
        model=ActivityLog
        fields=[
            "id",
            "integration_name",
            "event_type",
            "severity",
            "created_at"
        ]
