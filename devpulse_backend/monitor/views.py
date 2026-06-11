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

# Create your views here.

class RegisterView(APIView):
    permission_classes=[AllowAny]
    authentication_classes=[]
    def validate_username(self,username):
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
    
    def validate_password(self,password):
    
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
    
    def validate_email(self,email):
    
        if email is None:
            return False, "email key is missing in request."
            
        email = str(email).strip()

        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        
        if not re.match(email_pattern, email):
            return False, "Invalid email format. Please enter a valid email (e.g., name@example.com)."
            
        if User.objects.filter(email=email).exists():
            return False, "this email is already taken."
            
        return True, email  # Return the cleaned email string if successful

    def post(self,request):
        try:
            username=request.data.get("username")
            password=request.data.get("password")
            email=request.data.get("email")
          
            is_valid_user,user_result=self.validate_username(username)
            is_valid_pass,pass_result=self.validate_password(password)
            is_valid_email,email_result=self.validate_email(email)

            if not is_valid_user:
                return Response({
                    "status":"failed",
                    "message":user_result
                },status=status.HTTP_400_BAD_REQUEST)
            
            if not is_valid_pass:
                return Response({
                    "status":"failed",
                    "message":pass_result,
                },status=status.HTTP_400_BAD_REQUEST)
            
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

class ChangePasswordView(APIView):

    permission_classes = [IsAuthenticated]   

    def post(self,request):
        try:
            old_password = request.data.get("old_password")
            new_password = request.data.get("new_password")
            
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
            current_user.set_password(new_password)
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


class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        try:
            username = request.data.get("username")
            email = request.data.get("email")
            is_valid_user,user_result=self.validate_username(username)
            is_valid_email,email_result=self.validate_email(email)

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

            user = User.objects.get(username=username, email=email)

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

         
class ResetPassword(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self,request):
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
            
            token=PasswordResetToken.objects.get(token=reset_token)
            user=token.user
            user.set_password(new_password)
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


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self,request):
        try:
            refresh_token = request.data.get("refresh")

            if not refresh_token:
                return Response({
                    "status":"failed",
                    "message":"refresh_token is required."
                     },status=status.HTTP_400_BAD_REQUEST)
            
            token = RefreshToken(refresh_token)
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


class LogsView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self,request):
        try:
            logs=ActivityLog.objects.all().order_by("-created_at")
            severity=request.data.get("severity")
            event_type = request.data.get("event_type")
                                        
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
        

class WebhookReceiveView(APIView):
       
    permission_classes = [AllowAny]
    authentication_classes = []
    
    def post(self,request):
        try:
            id=request.data.get("id")
            integration =Integration.objects.get(id=id)
            received_token =request.headers.get("X-Webhook-Secret")
            event_type =request.data.get("event_type")
            severity =request.data.get("severity")
            
            if not integration.is_active:
                return Response({
                    "status": "failed",
                    "message":"This integration is currently disabled",
                     },status=status.HTTP_400_BAD_REQUEST)
            
            if received_token != integration.secret_token:
                return Response({
                    "status": "failed",
                    "message":"Invalid or missing secret token." ,
                     },status=status.HTTP_400_BAD_REQUEST)
            
            if not event_type:
                return Response({
                    "status": "failed",
                    "message": "event_type is required.",
                    },status=status.HTTP_400_BAD_REQUEST)
            
            allowed_severities = ["INFO", "WARNING", "CRITICAL"]

            if severity not in allowed_severities:
                return Response({
                    "status": "failed",
                    "message": f"severity must be one of: {allowed_severities}",
                    },status=status.HTTP_400_BAD_REQUEST)
            
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
        

class GitHubWebhookView(APIView):
     
     permission_classes = [AllowAny]
     authentication_classes = []
     
     def post(self,request,integration_id):
        try:
            integration=Integration.objects.get(id=integration_id, is_active=True)

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
            

            github_event=request.headers.get("X-Github-Event","unknown")

            if github_event == "ping":
                return Response({
                    "status":"success",
                    "message":"pong ! webhook is connected",
                },status=status.HTTP_200_OK)
            
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
            if github_event == "push":
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