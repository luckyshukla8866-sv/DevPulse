from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework.exceptions import AuthenticationFailed
from .models import BlacklistedAccessToken


class SafeJWTAuthentication(JWTAuthentication):
    """
    Same as normal JWT authentication, but ALSO checks
    if the access token has been blacklisted (by logout).
    """
    def authenticate(self, request):

        header = self.get_header(request)

        if header is None:
            raise AuthenticationFailed({
                "status": "failed",
                "message": "Access denied. Please provide a valid Bearer token in your Authorization header."
            })

        raw_token = self.get_raw_token(header)

        if raw_token is None:
            raise AuthenticationFailed({
                "status": "failed",
                "message": "Authorization token format is invalid. Use 'Bearer <token>'."
            })
        
        try:
            validated_token = self.get_validated_token(raw_token)

        except InvalidToken:
            raise AuthenticationFailed({
                "status":"failed",
                "mesaage":"Tokenhas experied"
            }) 

        # do the normal JWT check (is token valid? expired?)
        result = super().authenticate(request)

        # If no token was provided, return None (let other auth handle it)
        if result is None:
            return None
        
        # result is a tuple: (user, validated_token)
        user, validated_token = result

        token_generation_time = validated_token.get("iat")

        if user.last_login and token_generation_time:
            user_last_login_time = int(user.last_login.timestamp())
    
            if token_generation_time < user_last_login_time:
                raise AuthenticationFailed({
                    "status": "failed",
                    "message": "This token is no longer valid because a newer login session was created."
                })
        # 2. Decode and strip it cleanly into a plain string
        if isinstance(raw_token, bytes):
            token_string = raw_token.decode('utf-8').strip()
        else:
            token_string = str(raw_token).strip()

        # Check if this token is blacklisted
        if BlacklistedAccessToken.objects.filter(token=token_string).exists():
            raise AuthenticationFailed({
                "status":"failed",
                "mesaage":"This token has been logged out."
            })
    
        return (user, validated_token)
