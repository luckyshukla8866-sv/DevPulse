from celery import shared_task


@shared_task(name="monitor.send_critical_alert_notification")
def send_critical_alert_notification(event_type, message):
    """
    This function runs in Celery's terminal (Terminal 3),
    NOT in Django's terminal (Terminal 1).

    For now, it just prints. In the future, you'd replace
    print() with actual email sending code.
    """
    print("=" * 60)
    print("EMERGENCY ALERT — CRITICAL EVENT DETECTED!")
    print(f"   Event Type : {event_type}")
    print(f"   Message    : {message}")
    print("   Action     : Emergency Email Sent!")
    print("=" * 60)