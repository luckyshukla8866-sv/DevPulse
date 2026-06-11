from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from .models import ActivityLog,Integration,PasswordResetToken
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import ActivityLogSerializer
import re
import hashlib
import hmac

# ==========================================
# REUSABLE VALIDATION FUNCTIONS
# ==========================================

#Proper Validation for Username
def validate_username(username):
    if username is None:
        return False, "username is required."
    
    username = str(username).strip()
    
    if username == "":
        return False, "username cannot be empty or just spaces."
    if len(username) > 20:
        return False, "username is too long. Maximum 20 characters allowed."
    if len(username) < 3:
        return False, "username is too short. Minimum 3 characters required."
    
    for char in username:

        if char.isdigit():
            return False, "username cannot contain numbers."

        if not char.isalnum():
            return False, f"username cannot contain special characters or symbols. Found: '{char}'"
            
    if User.objects.filter(username=username).exists():
        return False, "this name is already taken."
        
    return True, username  

#Proper Validation for Password
def validate_password(password):

    if password is None:
        return False, "password key is missing in request."
    
    password = str(password)
    
    if password == "":
        return False, "password cannot be empty."
    if password.strip() == "":
        return False, "password cannot consist of only spaces."
    if len(password) < 6:
        return False, "password must be at least 6 characters long."
    if len(password) > 128:
        return False, "password is too long. Maximum 128 characters allowed."
        
    has_letter = False
    has_digit = False
    for char in password:
        if char.isalpha():
            has_letter = True
        if char.isdigit():
            has_digit = True
            
    if has_digit and not has_letter:
        return False, "password cannot be entirely numbers. Add some letters."
    if has_letter and not has_digit:
        return False, "password cannot be entirely letters. Add some numbers."
        
    return True, None

#Proper Validation for email
def validate_email(email):

    if email is None:
        return False, "email key is missing in request."
        
    email = str(email).strip()

    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    
    if not re.match(email_pattern, email):
        return False, "Invalid email format. Please enter a valid email (e.g., name@example.com)."
        
    if User.objects.filter(email=email).exists():
        return False, "this email is already taken."
        
    return True, email  # Return the cleaned email string if successful


# ============================================================
# VIEW 1: Register a New User
# URL: POST /api/v1/auth/register/
# ============================================================

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
            
            #----------Validations----------
            if old_password is None:
                    return Response({
                    "status":"failed",
                    "message":"old_password key is missing in request."
                },status=status.HTTP_400_BAD_REQUEST)
            
            if old_password == "":
                return Response({
                    "status":"failed",
                    "message":"old_password cannot be empty or just spaces."
                },status=status.HTTP_400_BAD_REQUEST)
            
            old_password = str(old_password)

            if new_password is None:
                    return Response({
                    "status":"failed",
                    "message":"new_password key is missing in request."
                },status=status.HTTP_400_BAD_REQUEST)
            
            if new_password == "":
                return Response({
                    "status":"failed",
                    "message":"new_password cannot be empty or just spaces."
                },status=status.HTTP_400_BAD_REQUEST)
               
            if len(new_password) < 6:
                return Response({
                    "status":"failed",
                    "message":"new password at least 6 characters."
                },status=status.HTTP_400_BAD_REQUEST)
            
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

            if not reset_token:
                return Response({
                    "status":"failed",
                    "message":"reset_token is required."
                },status=status.HTTP_400_BAD_REQUEST)
            
            if not new_password:
                return Response({
                    "status":"failed",
                    "message":"new_password  is required."
                },status=status.HTTP_400_BAD_REQUEST)
            
            if len(new_password) < 6:
                return Response({
                    "status":"failed",
                    "message":"new password at least 6 characters."
                },status=status.HTTP_400_BAD_REQUEST)
            
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
            integration=Integration.objects.get(id=integration_id, is_active=True)  # --- Find the integration ---

             # --- Verify the signature ---
            # GitHub signs the payload with your secret token using HMAC-SHA256
            # and sends the signature in the "X-Hub-Signature-256" header.
            # We recalculate the signature and compare to verify it's really from GitHub.
            signature_header = request.headers.get("X-Hub-Signature-256")

            if signature_header and integration.secret_token:
                expected_signature = "sha256=" + hmac.new(
                    key=integration .secret_token.encode("utf-8"),
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
            event_type,severity,message=self.parse_github_event(github_event,request.data)

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
                action = data.get("action", "created")
                user = data.get("sender", {}).get("login", "unknown")
                return (
                    "REPO_STARRED",
                    "INFO",
                    f"{user} starred the repository!",
                )
            
            else:
                # Any other event we haven't specifically handled
                return (
                    f"GITHUB_{github_event.upper()}",
                    "INFO",
                    f"GitHub event: {github_event}",
                )