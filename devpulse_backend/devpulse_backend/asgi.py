"""
ASGI config for devpulse_backend project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/asgi/
"""

import os
from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator
from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "devpulse.settings")
# This MUST come before importing your routing
django_asgi_app = get_asgi_application()
from monitor.routing import websocket_urlpatterns
application = ProtocolTypeRouter(
    {
        "http": django_asgi_app,                          # Normal HTTP → Django views
        "websocket": AllowedHostsOriginValidator(          # WebSocket → Channels
            AuthMiddlewareStack(
                URLRouter(websocket_urlpatterns)
            )
        ),
    }
)