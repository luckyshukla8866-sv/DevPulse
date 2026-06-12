from django.urls import re_path
from . import consumers

websocket_urlpatterns=[
    # When a browser connects to ws://localhost:8000/ws/live/feed/
    re_path(r"ws/live/feed/$",consumers.LiveFeedConsumer.as_asgi()),
]