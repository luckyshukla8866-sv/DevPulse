from django.urls import path
from .views import *
from django.views.generic import TemplateView

urlpatterns = [
    path("logs/",LogsView.as_view(), name="get-logs"),
    path("webhooks/receive/",WebhookReceiveView.as_view(),name="receive-webhook"),
    path("auth/register/",RegisterView.as_view(),name="register"),
    path("auth/change-password/",ChangePasswordView.as_view(), name="change-password"),
    path("auth/forget-password/",ForgotPasswordView.as_view(),name="forget_password"),
    path("auth/reset-password/",ResetPassword.as_view(),name="reset_password"),
    path("auth/logout/",LogoutView.as_view(), name="logout"),
    path("webhooks/github/<uuid:integration_id>/",GitHubWebhookView.as_view(), name="github-webhook"),
    path("dashboard/", TemplateView.as_view(template_name="dashboard.html"), name="dashboard"),
    path("webhooks/slack/<uuid:integration_id>/",SlackWebhookView.as_view(), name="slack-webhook"),
]