from django.db.models.signals import post_save
from django.dispatch import receiver
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .models import ActivityLog,SystemAlert
from .tasks import send_critical_alert_notification

@receiver(post_save,sender=ActivityLog)

def on_activity_log(sender,instance,created,**kwargs):
    """
    This function runs AUTOMATICALLY every time a new ActivityLog is saved.
    You never call this function directly — Django calls it for you.
    Parameters:
    - sender: The model that triggered the signal (ActivityLog)
    - instance: The actual log row that was just saved
    - created: True if this is a brand new row, False if an existing row was updated
    """
    # Only react to NEW logs, not edits to existing ones
    if not created:
        return
    
    print("="*10,"Signal","="*10)
    print("created",created)
    print("sender:",sender)
    print("instance:",instance)
    # --- PART 1: Send the new log to all dashboard browsers ---
    channel_layer =get_channel_layer()

    # Build a simple dictionary with the data we want to send
    log_data={                                                                                                                      
        "event_type":instance.event_type,
        "severity":instance.severity,
        "message":instance.payload.get("message"),
        "integration":instance.integration.name,
        "timestamp":instance.created_at.isoformat(),
    } 

    # Send it to the "live_feed" group (all connected browsers)
    async_to_sync(channel_layer.group_send)(
        "live_feed",
        {
            "type": "new_activity",    
            "data": log_data,
        },
    )

     # --- PART 2: If it's a CRITICAL event, create an alert and notify ---
    if instance.severity == "CRITICAL":
        SystemAlert.objects.create(activity_log=instance)   # Create a SystemAlert row in the database

          # Trigger the Celery background task
        send_critical_alert_notification.delay(
            event_type=instance.event_type,
            message=instance.payload.get("message","No details provided.")
        )
