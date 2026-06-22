from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from monitor.models import ActivityLog,Integration,PasswordResetToken,BlacklistedAccessToken
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from monitor.serializers import ActivityLogSerializer,CustomTokenObtainPairSerializer
from monitor.validations import validate_email,validate_password,validate_username,validate_old_password
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
          
            is_valid_user,user_result=validate_username(username,"username")
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
            is_valid_user,user_result=validate_username(username,"username")
            
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
