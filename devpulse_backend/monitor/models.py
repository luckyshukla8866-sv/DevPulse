from django.db import models
import uuid
from django.contrib.auth.models import User

#    Create your models here.
class Integration(models.Model):
    """
    Stores which external tools are connected to DevPulse.
    Example: "My GitHub Repository" with platform type "GITHUB"
    """

    # These are the only allowed platform types
    class PlatformChoices(models.TextChoices):
        GITHUB="GITHUB","GitHub"
        JIRA="JIRA","Jira"
        AWS="AWS","Aws"
        SLACK="SLACK", "Slack",

    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    name=models.CharField(max_length=200,help_text="Friendly name, e.g. 'Main GitHub Repo'")
    platform_type = models.CharField(max_length=10, choices=PlatformChoices.choices)
    secret_token = models.CharField(max_length=255, help_text="Shared secret for webhook verification")
    is_active=models.BooleanField(default=True)
    created_at=models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name},({self.platform_type})"


class ActivityLog(models.Model):
    """
    Every webhook event creates one row here.
    This is the main "history book" of all engineering activity.
    """
    class SeverityChoices(models.TextChoices):
        INFO="INFO","Info"
        WARNING="WARNING","Warning"
        CRITICAL="CRITICAL","Critical"

    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    integration=models.ForeignKey(Integration,on_delete=models.CASCADE,related_name="activity_logs")
    event_type=models.CharField(max_length=100,help_text="PULL_REQUEST_OPENED, SERVER_CRASH")
    severity=models.CharField(max_length=100,choices=SeverityChoices.choices,default=SeverityChoices.INFO)
    payload=models.JSONField(default=dict,help_text="Raw JSON data from external tool")

    created_at=models.DateTimeField(auto_now_add=True,db_index=True)


    def __str__(self):
        return f"[{self.severity}]{self.event_type}-{self.integration.name}"


class SystemAlert(models.Model):
    """
    Created automatically when a CRITICAL event arrives.
    Tracks whether the emergency has been resolved.
    """

    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    activity_log=models.OneToOneField(ActivityLog,on_delete=models.CASCADE,related_name="alert")
    is_resolved=models.BooleanField(default=False)
    resolved_at =models.DateTimeField(null=True,blank=True)

    def __str__(self):
        return f"Alert for {self.activity_log.event_type}"

class PasswordResetToken(models.Model):
    """
    Stores password reset tokens in the database.
    Each row = one forgot-password request.
    """
    token = models.UUIDField(default=uuid.uuid4, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Reset token for {self.user.username}"
    
class BlacklistedAccessToken(models.Model):
    """
    Stores access tokens that have been invalidated by logout.
    Each row = one logged-out access token.
    """
    token = models.TextField()
    blacklisted_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def __str__(self):
        return f"Blacklisted token at {self.blacklisted_at}"

