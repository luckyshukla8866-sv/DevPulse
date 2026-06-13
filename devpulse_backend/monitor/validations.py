from django.contrib.auth import get_user_model
import re

# ==========================================
# REUSABLE VALIDATION FUNCTIONS
# ==========================================

User = get_user_model()

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


def validate_old_password(old_password, user):
    """
    Validates all possible inputs for the old password field.
    Returns (True, old_password) or (False, error_message).
    """

    # 1. Check if the key is missing or null
    if old_password is None:
        return False, "old password is required."
    
    # Convert to string to prevent attribute errors if types vary
    old_password = str(old_password)
    
    # 2. Check if the password is an empty string
    if old_password == "":
        return False, "old password cannot be empty."
        
    # 3. Check if it consists only of spaces (e.g., "    ")
    if old_password.strip() == "":
        return False, "old password cannot consist of only spaces."

    # 4. Protect CPU from processing massive password hashing tasks
    if len(old_password) > 128:
        return False, "old password input is too long. Maximum 128 characters allowed."

    # 5. Run the cryptographic check against the database row hash
    if not user.check_password(old_password):
        return False, "The old password you entered is incorrect."

    return True, old_password
