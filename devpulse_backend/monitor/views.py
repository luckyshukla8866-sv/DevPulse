from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from .models import ActivityLog,Integration,PasswordResetToken
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import ActiivityLogSerializer
import re

# Create your views here.

class RegisterView(APIView):
    permission_classes=[AllowAny]
    authentication_classes=[]

    def post(self,request):
        try:
            username=request.data.get("username")
            password=request.data.get("password")
            email=request.data.get("email")

            if username is None:
                return Response({
                    "status":"failed",
                    "message":"username is required."
                },status=status.HTTP_400_BAD_REQUEST)
            
            username = str(username).strip()

            if username== "":
                return Response({
                "status": "failed",
                "message": "username cannot be empty or just spaces."
            }, status=status.HTTP_400_BAD_REQUEST)
   
            if len(username) > 20:
                return Response({
                "status": "failed",
                "message": "username is too long. Maximum 20 characters allowed."
            }, status=status.HTTP_400_BAD_REQUEST)

            if len(username) < 3:
                return Response({
                    "status": "failed",
                    "message": "username is too short. Minimum 3 characters required."
            }, status=status.HTTP_400_BAD_REQUEST)

            for char in username:

                if char.isdigit():
                    return Response({
                        "status": "failed",
                        "message": f"username cannot contain numbers."
                    },status=status.HTTP_400_BAD_REQUEST) 
                
                if not char.isalnum():
                    return Response({
                        "status": "failed",
                        "message": f"username cannot contain special characters or symbols. Found: '{char}'"
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            if User.objects.filter(username=username).exists():
                return Response({
                    "status":"failed",
                    "message":"this name is already taken."
                },status=status.HTTP_400_BAD_REQUEST)
            
            if password is None:
                return Response({
                    "status": "failed",
                    "message": "password key is missing in request."
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if password == "":
                return Response({
                    "status": "failed",
                    "message": "password cannot be empty."
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if password.strip() == "":
                return Response({
                    "status": "failed",
                    "message": "password cannot consist of only spaces."
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if len(password) < 6:
                return Response({
                    "status": "failed",
                    "message": "password must be at least 6 characters long."
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if len(password) > 128:
                return Response({
                    "status": "failed",
                    "message": "password is too long. Maximum 128 characters allowed."
                }, status=status.HTTP_400_BAD_REQUEST)
            
            has_letter = False
            has_digit = False
                
            for char in password:
                if char.isalpha():
                    has_letter = True
                if char.isdigit():
                    has_digit = True
                
            if has_digit and not has_letter:
                return Response({
                    "status": "failed",
                    "message": "password cannot be entirely numbers. Add some letters"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if has_letter and not has_digit:
                return Response({
                    "status":"failed",
                    "message": "password cannot be entirely letters. Add some numbers"
                }, status=status.HTTP_400_BAD_REQUEST)

            if email is None:
                return Response({
                    "status":"failed",
                    "message":"email key is missing in request."
                }, status=status.HTTP_400_BAD_REQUEST)
            
            email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

            if not re.match(email_pattern, email):
                return Response({
                    "status": "failed",
                    "message": "Invalid email format. Please enter a valid email (e.g., name@example.com)."
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if User.objects.filter(email=email).exists():
                return Response({
                    "status":"failed",
                    "message":"this email is already taken."
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
        
    def get(self,requwst):
        try:
            users=User.objects.all()
            print(users)
            user_data=[]
            for user in users:
                data={
                    "name":user.username
                }
                user_data.append(data)

            return Response(user)
        
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

            if not username:
                return Response({
                    "status":"failed",
                    "message":"username  is required."
                },status=status.HTTP_400_BAD_REQUEST)

            if not email:
                return Response({
                    "status":"failed",
                    "message":"email  is required."
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

            serializers=ActiivityLogSerializer(logs,many=True)
    
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
       
    permission_classes = [IsAuthenticated]
    
    def post(self,request):
        try:
            id=request.objects.get("id")
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
        


