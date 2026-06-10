from django.db.models.signals import post_save
from django.dispatch import receiver
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .models import ActivityLog,SystemAlert
from .tasks import send_critical_alert_notification

@receiver(post_save,sender=ActivityLog)

def on_activity_log(sender,instance,created,**kwargs):
    if not created:
        return
    
    channel=get_channel_layer()

    log_data={
        "event_type":instance.event_type,
        "severity":instance.severity,
        "message":instance.payload.get("message"),
        "integration":instance.integration.name,
        "timestamp":instance.created_at.isoformat(),
    } 

    if instance.severity == "CRITICAL":
        SystemAlert.objects.create(activity_log=instance)

        send_critical_alert_notification.delay(
            event_type=instance.event_type,
            message=instance.payload.get("message","No details provided.")
        )
