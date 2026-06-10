from django.urls import path
from .views import *

urlpatterns = [
    path("logs/",LogsView.as_view(), name="get-logs"),
    path("webhooks/receive/<uuid:id>/",WebhookReceiveView.as_view(),name="receive-webhook"),
    path("auth/register/",RegisterView.as_view(),name="register"),
    path("auth/change-password/",ChangePasswordView.as_view(), name="change-password"),
    path("auth/forget-password/",ForgotPasswordView.as_view(),name="forget_password"),
    path("auth/reset-password/",ResetPassword.as_view(),name="reset_password"),
    path("auth/logout/",LogoutView.as_view(), name="logout"),
]