from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from .models import ActivityLog,Integration,PasswordResetToken,BlacklistedAccessToken
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import ActivityLogSerializer
import hashlib
import hmac
from .validations import validate_email,validate_password,validate_username,validate_old_password
from django.contrib.auth import get_user_model
from datetime import datetime, timezone

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
            is_valid_email,email_result=validate_email(email)

            if not is_valid_user:
                return Response({
                    "status":"failed",
                    "message":user_result
                },status=status.HTTP_400_BAD_REQUEST)
            
            
            if not is_valid_email:
                return Response({
                    "status":"failed",
                    "message":email_result,
                },status=status.HTTP_400_BAD_REQUEST)

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
            is_valid_pass, pass_result = validate_old_password(new_password)

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
                "message":"Invalid or expired reset token."
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
            print("***Step1***")
            refresh_token = request.data.get("refresh")
            print("***Step2***")
            if not refresh_token:
                return Response({
                    "status":"failed",
                    "message":"refresh_token is required."
                     },status=status.HTTP_400_BAD_REQUEST)
            print("***Step3***")
            token = RefreshToken(refresh_token) # Create a RefreshToken object and blacklist it
            token.blacklist()
            print("***Step4***")
            auth_header=request.headers.get("Authorization")
            print("***Step5***")
            if auth_header.startswith("Bearer "):
                print("***Step6***")
                access_token =auth_header.replace("Bearer ", "").strip()
                print("***Step7***")
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
            print("***step1***")
            integration=Integration.objects.get(id=integration_id, is_active=True)  # --- Find the integration ---
            print("integration:",integration)
             # --- Verify the signature ---
            # GitHub signs the payload with your secret token using HMAC-SHA256
            # and sends the signature in the "X-Hub-Signature-256" header.
            # We recalculate the signature and compare to verify it's really from GitHub.
            print("***step2***")
            signature_header = request.headers.get("X-Hub-Signature-256")
            print("signature_header:",signature_header)
            print("integration.secret_token:",integration.secret_token)
            if signature_header and integration.secret_token:
                print("***step3***")
                expected_signature = "sha256=" + hmac.new(
                    key=integration.secret_token.encode("utf-8"),
                    msg=request.body,
                    digestmod=hashlib.sha256,
                ).hexdigest()
                print("integration .secret_token.encode(utf-8):",integration .secret_token.encode("utf-8"))
                print("expected_signature:",expected_signature)
                print("***step4***")
                print("signature_header:\n",signature_header)
                print("expected_signature\n",expected_signature)
                if not hmac.compare_digest(signature_header,expected_signature):
                    return Response({
                        "status":"failed",
                        "message":"invalid signature"
                    },status=status.HTTP_404_NOT_FOUND)
            
            # --- Read the GitHub event type ---
            # GitHub tells us WHAT happened via the "X-GitHub-Event" header
            github_event=request.headers.get("X-Github-Event","unknown")
            print("github_event:",github_event)
            if github_event == "ping":
                return Response({
                    "status":"success",
                    "message":"pong ! webhook is connected",
                },status=status.HTTP_200_OK)
            
            # --- Translate GitHub's data to our format ---
            print("step5")
            event_type,severity,message=self.parse_github_event(github_event,request.data)
            print("event_type:",event_type) 
            print("severity:",severity)
            print("message:",message)
            print("="*10,"Data","="*10)
            print(request.data)
            # Add the parsed message to the payload so the signal/dashboard can read it
            payload = dict(request.data)
            payload["message"] = message
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
            print("********Step:1********")
            if github_event == "push":
                # Someone pushed code to the repository
                pusher=data.get("pusher",{}).get("name","unknown")
                branch = data.get("ref", "").replace("refs/heads/", "")
                commits_count = len(data.get("commits", []))

                return (
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
                    f"ISSUE_{action.upper()}",
                    "WARNING" if action == "opened" else "INFO",
                    f"{user}: {title}",
                )

            elif github_event == "star":
                # Someone starred the repository
                print("********Step:2********")
                action = data.get("action", "created")
                print("action",action)
                user = data.get("sender", {}).get("login", "unknown")
                print("user",user)
                name=data.get("name","None")
                print("name:",name)
                return (
                    "REPO_STARRED",
                    "INFO",
                    f"{user} {action} the repository!",
                )
            
            else:
                # Any other event we haven't specifically handled
                return (
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
        """
        Handles real events from Slack.
        Slack sends two types of requests:
        1. URL verification (first time only) — we echo back the challenge
        2. Event callbacks (real events) — we save them to the database
        """
        print("Step1")
        # --- Handle URL Verification ---
        # When you first add the URL in Slack, Slack sends a "challenge"
        # to make sure your server is real. You just send it back.
        if request.data.get("type") == "url_verification":
            challenge = request.data.get("challenge", "")
            return Response(
                {"challenge": challenge},
                status=status.HTTP_200_OK,
            )

        # --- STEP 2: Find the integration ---
        try:
            integration = Integration.objects.get(id=integration_id, is_active=True)
        except Integration.DoesNotExist:
            return Response(
                {"error": "Integration not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        
        # Slack wraps the actual event inside an "event" key
        slack_event = request.data.get("event", {})
        event_type_raw = slack_event.get("type", "unknown")

        # Ignore bot messages (to avoid infinite loops if you add a bot later)
        if slack_event.get("bot_id"):
            return Response({"status": "ignored", "message": "Bot message ignored."})

        # --- Translate Slack's format to our format ---
        event_type, severity, message = self.parse_slack_event(event_type_raw, slack_event)

        # --- Save to database ---
        payload = dict(request.data)
        payload["message"] = message

        ActivityLog.objects.create(
            integration=integration,
            event_type=event_type,
            severity=severity,
            payload=payload,
        )

        return Response(
            {"status": "success", "message": f"Slack event received!"},
            status=status.HTTP_202_ACCEPTED,
        )

    def parse_slack_event(self, event_type_raw, slack_event):
        """
        Translates Slack's event format to our event_type, severity, message.
        """

        if event_type_raw == "message":
            # Someone posted a message in a channel
            user = slack_event.get("user", "unknown")
            text = slack_event.get("text", "No text")
            channel = slack_event.get("channel", "unknown")
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