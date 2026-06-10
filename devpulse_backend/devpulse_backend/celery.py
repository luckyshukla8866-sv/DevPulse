import os
from celery import Celery

# Tell Celery which Django settings to use
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "devpulse_backend.settings")

# Create the Celery app — the name should match your project
app = Celery("devpulse_backend")

app.config_from_object("django.conf:settings", namespace="CELERY")

app.autodiscover_tasks()
