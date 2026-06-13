from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import BlacklistedAccessToken

class SafeJWTAuthentication(JWTAuthentication):
    """
    Same as normal JWT authentication, but ALSO checks
    if the access token has been blacklisted (by logout).
    """
    def authenticate(self, request):
        print("*** Step 1 ***")
        # do the normal JWT check (is token valid? expired?)
        result = super().authenticate(request)
        print(result)
        print("*** Step 2 ***")
        # If no token was provided, return None (let other auth handle it)
        if result is None:
            return None
        print("*** Step 3 ***")
        # result is a tuple: (user, validated_token)
        user, validated_token = result
        print("*** Step 4 ***")
        # Get the raw token string from the header
        raw_token = self.get_raw_token(self.get_header(request))

        # 2. Decode and strip it cleanly into a plain string
        if isinstance(raw_token, bytes):
            token_string = raw_token.decode('utf-8').strip()
        else:
            token_string = str(raw_token).strip()

        print("*** Step 5 ***")
        # Check if this token is blacklisted
        if BlacklistedAccessToken.objects.filter(token=token_string).exists():
            raise AuthenticationFailed("This token has been logged out.")
        
        return (user, validated_token)