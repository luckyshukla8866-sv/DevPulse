from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from .models import ActivityLog,Integration,PasswordResetToken,BlacklistedAccessToken
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import ActivityLogSerializer,CustomTokenObtainPairSerializer
import hashlib
import hmac
from .validations import validate_email,validate_password,validate_username,validate_old_password
from django.contrib.auth import get_user_model
from datetime import datetime, timezone
from rest_framework_simplejwt.views import TokenObtainPairView
import re

# ============================================================
# VIEW 1: Register a New User
# URL: POST /api/v1/auth/register/
# ============================================================
User = get_user_model()

class RegisterView(APIView):
    """
    Creates a new user account.
    """
    permission_classes=[AllowAny]   # Anyone can access
    authentication_classes=[]       # Don't even try to authenticate

    def post(self,request):
        try:
            # Grab raw incoming data from Postman
            username=request.data.get("username")
            password=request.data.get("password")
            email=request.data.get("email")
          
            is_valid_user,user_result=validate_username(username)
            is_valid_pass,pass_result=validate_password(password)
            is_valid_email,email_result=validate_email(email)

            # Run Username Validation
            if not is_valid_user:
                return Response({
                    "status":"failed",
                    "message":user_result
                },status=status.HTTP_400_BAD_REQUEST)
            
            # Run Password Validation
            if not is_valid_pass:
                return Response({
                    "status":"failed",
                    "message":pass_result,
                },status=status.HTTP_400_BAD_REQUEST)
            
            # Run Email Validation
            if not is_valid_email:
                return Response({
                    "status":"failed",
                    "message":email_result,
                },status=status.HTTP_400_BAD_REQUEST)
            
            
            user=User.objects.create_user(username=username,password=password,email=email)

            return Response({
                "status":"success",
                "message":f"account created for {username},now you can login",
            },status=status.HTTP_201_CREATED)
        
        except Exception as e:
            return Response({
                "status":"error",
                "message":str(e)
            },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def get(self,request):
        try:
            raw_users = User.objects.values("username", "email")

            user_list=list(raw_users)

            return Response({
                "status":"success",
                "message":"fect successfully the user details",
                "data":user_list,
            },status=status.HTTP_200_OK)
        
        except  Exception as e:
             return Response({
                "status":"error",
                "message":str(e)
            },status=status.HTTP_500_INTERNAL_SERVER_ERROR)



# ============================================================
# VIEW 2: Login 
# URL: POST /api/v1/auth/token/ 
# ============================================================        
class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


# ============================================================
# VIEW 2: Change Password (user is logged in)
# URL: POST /api/v1/auth/change-password/
# ============================================================

class ChangePasswordView(APIView):

    permission_classes = [IsAuthenticated]  # Must be logged in 

    def post(self,request):
        """
        User knows their old password and wants to change it.
        Send: old_password, new_password
        """
        try:
            old_password = request.data.get("old_password")
            new_password = request.data.get("new_password")
            current_user=request.user
            is_valid_old, old_pass_result = validate_old_password(old_password, current_user)
            is_valid_pass, pass_result = validate_password(new_password)
            #----------Validations----------
            
            if not is_valid_old:
                return Response({
                    "status": "failed",
                    "message": old_pass_result
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if not is_valid_pass:
                return Response({
                    "status": "failed",
                    "message": pass_result
                }, status=status.HTTP_400_BAD_REQUEST) 
            
            if old_password == new_password:
                return Response({
                    "status": "failed",
                    "message": "Your new password cannot be the same as your old password."
                }, status=status.HTTP_400_BAD_REQUEST)
            
            
            current_user = request.user
            current_user.set_password(new_password) # Set the new password (Django automatically hashes it)
            current_user.save()
            
            return Response({
                "status":"success",
                "message":f"Password changed successfully! {new_password}.",
            },status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({
                "status":"error",
                "message":str(e)
            },status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============================================================
# VIEW 3: Forgot Password (user is NOT logged in)
# URL: POST /api/v1/auth/forgot-password/
# ============================================================

class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        """
        User forgot their password.
        Send: username, email
        If both match, we generate a reset token.
        In a real app, this token would be sent via EMAIL.
        For testing, we return it directly in the response.
        """
        try:
            username = request.data.get("username")
            email = request.data.get("email")
            is_valid_user,user_result=validate_username(username)
            
            if not is_valid_user:
                return Response({
                    "status":"failed",
                    "message":user_result
                },status=status.HTTP_400_BAD_REQUEST)
            
            
            if email is None:
                return False, "email key is missing in request."
        
            email = str(email).strip()

            email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            
            if not re.match(email_pattern, email):
                return False, "Invalid email format. Please enter a valid email (e.g., name@example.com)."

            # Check if a user with this username AND email exists
            user = User.objects.get(username=username, email=email)  

            # Create a reset token and save it IN THE DATABASE 
            reset_token=PasswordResetToken.objects.create(user=user)    
            
            return Response({
                "status": "success",
                "message": "password reset token generated.",
                "reset_token": str(reset_token.token),
            },status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({
                 "status":"error",
                "message":"no account found with this username and email."
            },status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "status":"error",
                "message":str(e)
            },status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============================================================
# VIEW 4: Reset Password (using the token from forgot-password)
# URL: POST /api/v1/auth/reset-password/
# ============================================================
      
class ResetPassword(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self,request):
        """
        User received a reset token and now sets a new password.
        Send: reset_token, new_password
        """
        try:
            reset_token = request.data.get("reset_token")
            new_password = request.data.get("new_password")
            is_valid_pass, pass_result = validate_password(new_password)

            if not reset_token:
                return Response({
                    "status":"failed",
                    "message":"reset_token is required."
                },status=status.HTTP_400_BAD_REQUEST)
            
            if not is_valid_pass:
                return Response({
                    "status": "failed",
                    "message": pass_result
                }, status=status.HTTP_400_BAD_REQUEST)            
            
            # Look up the token IN THE DATABASE
            token=PasswordResetToken.objects.get(token=reset_token)
            user=token.user
            user.set_password(new_password) # Get the user and set the new password
            user.save()

            token.delete()

            return Response({
                "status": "success",
                "message": f"Password reset successfully for '{user.username}'.",
                },status=status.HTTP_200_OK)
        
        except PasswordResetToken.DoesNotExist:
            return Response({
                 "status":"error",
                "message":"User not found."
            },status=status.HTTP_404_NOT_FOUND)
             
        except Exception as e:
            return Response({
                "status":"error",
                "message":str(e)
            },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# ============================================================
# VIEW 5: Logout (blacklist the refresh token)
# URL: POST /api/v1/auth/logout/
# ============================================================

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self,request):
        """
        Logs out the user by blacklisting their refresh token.
        Send: refresh (the refresh token you got at login)
        """
        try:
            refresh_token = request.data.get("refresh")

            if not refresh_token:
                return Response({
                    "status":"failed",
                    "message":"refresh_token is required."
                     },status=status.HTTP_400_BAD_REQUEST)

            token = RefreshToken(refresh_token) # Create a RefreshToken object and blacklist it
            token.blacklist()

            auth_header=request.headers.get("Authorization")

            if auth_header.startswith("Bearer "):
                access_token =auth_header.replace("Bearer ", "").strip()
                
                BlacklistedAccessToken.objects.create(
                    token=access_token,
                    expires_at=datetime.now(timezone.utc),
                )
            return Response({
                "status":"success",
                "message":"Logged out successfully."
            },status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status":"error",
                "message":str(e)
            },status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============================================================
# VIEW 6: Get History Logs
# URL: POST /api/v1/logs/
# ============================================================
class LogsView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self,request):
        """
        Returns a list of activity logs.
        Users can filter by sending JSON in the request body:
        {
            "severity": "CRITICAL",
            "integration_id": "abc-123",
            "event_type": "SERVER_CRASH"
        }
        All filter fields are optional — send an empty {} to get all logs.
        """
        try:
            logs=ActivityLog.objects.all().order_by("-created_at")  # Start with ALL logs, newest first            
            severity=request.data.get("severity")
            event_type = request.data.get("event_type")

            # --- FILTERING ---                        
            if severity:
                logs = logs.filter(severity=severity)

            if event_type:
                logs=logs.filter(event_type=event_type)

            serializers=ActivityLogSerializer(logs,many=True)
    
            return Response({
                "status":"success",
                "message":"data fetch successfully ",
                "data":serializers.data,
            })

        except Exception as e:
            return Response({
                "status":"error",
                "message":str(e)
            },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

# ============================================================
# VIEW 6B: Dashboard History (no auth needed — used by the HTML page)
# URL: GET /api/v1/dashboard/history/
# ============================================================
class DashboardHistoryView(APIView):
    """
    Returns the last 50 logs in the SAME format as the WebSocket signal,
    so the dashboard can display them on page load.
    No authentication required because the dashboard page itself has no login.
    """
    
    permission_classes = [AllowAny]
    authentication_classes = []

    def get(self, request):
        try:
            logs = ActivityLog.objects.select_related("integration").order_by("-created_at")[:50]

            results = []
            for log in logs:
                results.append({
                    "event_type": log.event_type,
                    "severity": log.severity,
                    "message": log.payload.get("message", "No message"),
                    "integration": log.integration.name,
                    "repo_name": log.payload.get("repo_name", log.integration.name),
                    "timestamp": log.created_at.isoformat(),
                })

            return Response({"data": results}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": "error",
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# ============================================================
# VIEW  7: Receive Webhook Data
# URL: POST /api/v1/webhooks/receive/<uuid:integration_id>/
# ============================================================
class WebhookReceiveView(APIView):
       
    permission_classes = [AllowAny]
    authentication_classes = []
    
    def post(self,request):
        try:
            id=request.data.get("id")
            integration =Integration.objects.get(id=id)   # --- Find the integration ---
            received_token =request.headers.get("X-Webhook-Secret")
            event_type =request.data.get("event_type")
            severity =request.data.get("severity")
            
            if not integration.is_active:   # ---  Check if the integration is active ---
                return Response({
                    "status": "failed",
                    "message":"This integration is currently disabled",
                     },status=status.HTTP_400_BAD_REQUEST)
            
            if received_token != integration.secret_token:  # --- Verify the secret token ---
                return Response({
                    "status": "failed",
                    "message":"Invalid or missing secret token." ,
                     },status=status.HTTP_400_BAD_REQUEST)
            
            if not event_type:
                return Response({
                    "status": "failed",
                    "message": "event_type is required.",
                    },status=status.HTTP_400_BAD_REQUEST)
            
            allowed_severities = ["INFO", "WARNING", "CRITICAL"]    # Check that severity is one of the allowed values

            if severity not in allowed_severities:   # Read the JSON data from the request body ---
                return Response({
                    "status": "failed",
                    "message": f"severity must be one of: {allowed_severities}",
                    },status=status.HTTP_400_BAD_REQUEST)
            
            # --- STEP 5: Save the new ActivityLog to the database ---
            ActivityLog.objects.create(integration=integration,event_type=event_type,severity=severity,payload=request.data)
    
            return Response({
                    "status": "success",
                    "message": "Data received! We are processing it now.",
                },status=status.HTTP_202_ACCEPTED)

        except Integration.DoesNotExist:
            return Response(
                {"error": "Integration not found."},
                status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "status":"error",
                "message":str(e)
            },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

# ============================================================
# VIEW 8: Receive REAL GitHub Webhooks
# URL: POST /api/v1/webhooks/github/<uuid:integration_id>/
# ============================================================
class GitHubWebhookView(APIView):
     
     permission_classes = [AllowAny]
     authentication_classes = []
     
     def post(self,request,integration_id):
        try:
            integration=Integration.objects.get(id=integration_id, is_active=True)  # --- Find the integration ---

             # --- Verify the signature ---
            # GitHub signs the payload with your secret token using HMAC-SHA256
            # and sends the signature in the "X-Hub-Signature-256" header.
            # We recalculate the signature and compare to verify it's really from GitHub.

            signature_header = request.headers.get("X-Hub-Signature-256")

            if signature_header and integration.secret_token:
                expected_signature = "sha256=" + hmac.new(
                    key=integration.secret_token.encode("utf-8"),
                    msg=request.body,
                    digestmod=hashlib.sha256,
                ).hexdigest()

                if not hmac.compare_digest(signature_header,expected_signature):
                    return Response({
                        "status":"failed",
                        "message":"invalid signature"
                    },status=status.HTTP_404_NOT_FOUND)
            
            # --- Read the GitHub event type ---
            # GitHub tells us WHAT happened via the "X-GitHub-Event" header
            github_event=request.headers.get("X-Github-Event","unknown")

            if github_event == "ping":
                return Response({
                    "status":"success",
                    "message":"pong ! webhook is connected",
                },status=status.HTTP_200_OK)
            
            # --- Translate GitHub's data to our format ---
            repo_name,event_type,severity,message=self.parse_github_event(github_event,request.data)
            
            # Add the parsed message and repo name to the payload so the signal/dashboard can read it
            payload = dict(request.data)
            payload["message"] = message
            payload["repo_name"] = repo_name
            ActivityLog.objects.create(integration=integration,event_type=event_type,severity=severity,payload=payload)
    
            return Response({
                "status":"success",
                "message":f"GitHub {github_event} event received!"
            }, status=status.HTTP_202_ACCEPTED,)

        except Integration.DoesNotExist:
            return Response({
                "status":"failed",
                "message":"Integration not found or inactive."
            }, status=status.HTTP_404_NOT_FOUND)
        
        except Exception as e:
            return Response({
                "status":"error",
                "message":str(e)
            },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    
     def parse_github_event(self, github_event, data):
            """
            Translates GitHub's event format to our event_type, severity, message.
            
            GitHub sends different JSON for each event type.
            This function reads the right fields from each type.
            """
            repo_name = data.get("repository", {}).get("name", "unknown-repo")
            print(repo_name)
            if github_event == "push":
                # Someone pushed code to the repository
                pusher=data.get("pusher",{}).get("name","unknown")
                branch = data.get("ref", "").replace("refs/heads/", "")
                commits_count = len(data.get("commits", []))

                return (
                    repo_name,
                    "CODE_PUSH",
                    "INFO",
                    f"{pusher} pushed {commits_count} commit(s) to {branch}",
                )
                    
            elif github_event == "pull_request":
                # Someone opened/closed/merged a pull request
                action = data.get("action", "unknown")
                pr = data.get("pull_request", {})
                title = pr.get("title", "No title")
                user = pr.get("user", {}).get("login", "unknown")
                return (
                    repo_name,
                    f"PULL_REQUEST_{action.upper()}",
                    "INFO",
                    f"{user}: {title}",
                )
            
            elif github_event == "issues":
                # Someone created/closed an issue
                action = data.get("action", "unknown")
                issue = data.get("issue", {})
                title = issue.get("title", "No title")
                user = issue.get("user", {}).get("login", "unknown")
                return (
                    repo_name,
                    f"ISSUE_{action.upper()}",
                    "WARNING" if action == "opened" else "INFO",
                    f"{user}: {title}",
                )

            elif github_event == "star":
                # Someone starred the repository
                action = data.get("action", "created")
                user = data.get("sender", {}).get("login", "unknown")
                return (
                    repo_name,
                    "REPO_STARRED",
                    "INFO",
                    f"{user} {action} the repository!",
                )
            
            else:
                # Any other event we haven't specifically handled
                return (
                    repo_name,
                    f"GITHUB_{github_event.upper()}",
                    "INFO",
                    f"GitHub event: {github_event}",
                )
            
# ============================================================
# VIEW 9: Receive REAL Slack Events
# URL: POST /api/v1/webhooks/slack/<uuid:integration_id>/
# ============================================================

class SlackWebhookView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request, integration_id):
        try:
            """
            Handles real events from Slack.
            Slack sends two types of requests:
            1. URL verification (first time only) — we echo back the challenge
            2. Event callbacks (real events) — we save them to the database
            """
            # --- Handle URL Verification ---
            if request.data.get("type") == "url_verification":
                challenge = request.data.get("challenge", "")
                return Response(
                    {"challenge": challenge},
                    status=status.HTTP_200_OK,
                )
            # --- Find the integration ---
            try:
                integration = Integration.objects.get(id=integration_id, is_active=True)
                print("Model:",integration)
            except Integration.DoesNotExist:
                return Response(
                    {"error": "Integration not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )
            
            # --- Parse the Slack event ---
            slack_event = request.data.get("event", {})
            event_type_raw = slack_event.get("type", "unknown")
         
            # Ignore bot messages (to avoid infinite loops if you add a bot later)
            if slack_event.get("bot_id"):
                return Response({"status": "ignored", "message": "Bot message ignored."})
         
            # --- Translate Slack's format to our format ---
            event_type, severity, message = self.parse_slack_event(event_type_raw, slack_event)
            print("event_type:",event_type)
            print("severity:",severity)
            print("message:",message)
            # --- Save to database ---
            print("****step5****")
            payload = dict(request.data)
            payload["message"] = message
            print("playload:",payload)

            ActivityLog.objects.create(
                integration=integration,
                event_type=event_type,
                severity=severity,
                payload=payload,
            )

            return Response(
                {"status": "success",
                 "message": f"Slack event received!"},
                status=status.HTTP_202_ACCEPTED,
            )
        except Exception as e:
            return Response({
                "status": "error",
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def parse_slack_event(self, event_type_raw, slack_event):
        """
        Translates Slack's event format to our event_type, severity, message.
        """
        print("="*10,"Slack_Fun","="*10)
        print("event_type_raw",event_type_raw)
        print("slack_event",slack_event)
        if event_type_raw == "message":
            # Someone posted a message in a channel
            user = slack_event.get("user", "unknown")
            print("user:",user)
            text = slack_event.get("text", "No text")
            print("text:",text)
            channel = slack_event.get("channel", "unknown")
            print("chennal:",channel)
            return (
                "SLACK_MESSAGE",
                "INFO",
                f"User {user} in #{channel}: {text}",
            )

        elif event_type_raw == "member_joined_channel":
            # Someone joined a channel
            user = slack_event.get("user", "unknown")
            channel = slack_event.get("channel", "unknown")
            return (
                "SLACK_MEMBER_JOINED",
                "INFO",
                f"User {user} joined #{channel}",
            )

        elif event_type_raw == "reaction_added":
            # Someone added an emoji reaction
            user = slack_event.get("user", "unknown")
            reaction = slack_event.get("reaction", "unknown")
            return (
                "SLACK_REACTION",
                "INFO",
                f"User {user} reacted with :{reaction}:",
            )

        elif event_type_raw == "channel_created":
            # A new channel was created
            channel_info = slack_event.get("channel", {})
            name = channel_info.get("name", "unknown")
            return (
                "SLACK_CHANNEL_CREATED",
                "WARNING",
                f"New channel created: #{name}",
            )

        else:
            return (
                f"SLACK_{event_type_raw.upper()}",
                "INFO",
                f"Slack event: {event_type_raw}",
            )

# ============================================================
# VIEW 10: Receive REAL Jira Webhooks
# URL: POST /api/v1/webhooks/jira/<uuid:integration_id>/
# ============================================================

class JiraWebhookView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request, integration_id):
        """
        Handles real webhooks from Jira.
        Jira sends a POST request every time something changes
        (issue created, updated, deleted, commented, etc.)
        """
        # --- Find the integration ---
        try:
            integration = Integration.objects.get(id=integration_id, is_active=True)
        except Integration.DoesNotExist:
            return Response(
                {"error": "Integration not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
       
        
        # --- Read the Jira event type ---
        # Jira sends the event name in a field called "webhookEvent"
      
        webhook_event = request.data.get("webhookEvent", "unknown")
        # --- STEP 3: Translate Jira's format to our format ---
        event_type, severity, message = self.parse_jira_event(webhook_event, request.data)

        # --- STEP 4: Save to database ---
        payload = dict(request.data)
        payload["message"] = message
        
        ActivityLog.objects.create(
            integration=integration,
            event_type=event_type,
            severity=severity,
            payload=payload,
        )

        return Response({
            "status": "success", 
            "message": f"Jira event received: {webhook_event}"
            },status=status.HTTP_202_ACCEPTED,)

    def parse_jira_event(self, webhook_event, data):
        """
        Translates Jira's event format to our event_type, severity, message.
        """
        print("*****step1*****")
        print("Data:",data)
        # Get common fields that most Jira events have
        user = data.get("user", {}).get("displayName", "Unknown")
        issue = data.get("issue", {})
        issue_key = issue.get("key", "")
        fields = issue.get("fields", {})
        summary = fields.get("summary", "No summary")
        priority = fields.get("priority", {}).get("name", "Normal")
        issue_type = fields.get("issuetype", {}).get("name", "Task")
        
        # Decide severity based on Jira priority
        if priority in ["Highest", "Critical"]:
            severity = "CRITICAL"
        elif priority in ["High"]:
            severity = "WARNING"
        else:
            severity = "INFO"

        if webhook_event == "jira:issue_created":
            return (
                "JIRA_ISSUE_CREATED",
                severity,
                f"{user} created {issue_type} {issue_key}: {summary}",
            )

        elif webhook_event == "jira:issue_updated":
            # Check if the status changed (e.g., "To Do" → "In Progress")
            changelog = data.get("changelog", {})
            items = changelog.get("items", [])
            status_change = ""
            for item in items:
                if item.get("field") == "status":
                    old_status = item.get("fromString", "?")
                    new_status = item.get("toString", "?")
                    status_change = f" [{old_status} → {new_status}]"
                    break

            return (
                "JIRA_ISSUE_UPDATED",
                severity,
                f"{user} updated {issue_key}: {summary}{status_change}",
            )

        elif webhook_event == "jira:issue_deleted":
            return (
                "JIRA_ISSUE_DELETED",
                "WARNING",
                f"{user} deleted {issue_key}: {summary}",
            )

        elif webhook_event == "comment_created":
            comment_body = data.get("comment", {}).get("body", "No comment text")
            # Jira comments can be very long, so we take first 100 characters
            short_comment = comment_body[:100]
            return (
                "JIRA_COMMENT_ADDED",
                "INFO",
                f"{user} commented on {issue_key}: {short_comment}",
            )

        elif webhook_event == "comment_updated":
            return (
                "JIRA_COMMENT_UPDATED",
                "INFO",
                f"{user} edited a comment on {issue_key}",
            )

        elif webhook_event == "issuelink_created":
            return (
                "JIRA_LINK_CREATED",
                "INFO",
                f"{user} linked {issue_key} to another issue",
            )

        else:
            return (
                f"JIRA_{webhook_event.upper().replace(':', '_')}",
                "INFO",
                f"Jira event: {webhook_event} by {user}",
            )