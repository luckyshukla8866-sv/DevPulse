from django.urls import path
from .views import *
from django.views.generic import TemplateView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path("auth/register/",RegisterView.as_view(),name="register"),
    path("auth/token/", CustomTokenObtainPairView.as_view(), name="token-obtain"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("auth/change-password/",ChangePasswordView.as_view(), name="change-password"),
    path("auth/forget-password/",ForgotPasswordView.as_view(),name="forget_password"),
    path("auth/reset-password/",ResetPassword.as_view(),name="reset_password"),
    path("logs/",LogsView.as_view(), name="get-logs"),
    path("webhooks/receive/",WebhookReceiveView.as_view(),name="receive-webhook"),
    path("webhooks/github/<uuid:integration_id>/",GitHubWebhookView.as_view(), name="github-webhook"),
    path("webhooks/slack/<uuid:integration_id>/",SlackWebhookView.as_view(), name="slack-webhook"),
    path("dashboard/", TemplateView.as_view(template_name="dashboard.html"), name="dashboard"),
    path("dashboard/history/",DashboardHistoryView.as_view(), name="dashboard-history"),
    path("auth/logout/",LogoutView.as_view(), name="logout"),
]

