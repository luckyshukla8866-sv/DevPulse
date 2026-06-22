from django.contrib.auth import get_user_model
import re
from datetime import datetime, time

# ==========================================
# REUSABLE VALIDATION FUNCTIONS
# ==========================================

User = get_user_model()

#Proper Validation for Username
def validate_username(username,filed):
    if username is None:
        return False, f"{filed} is required."
    
    username = str(username).strip()
    
    if username == "":
        return False, f"{filed} cannot be empty or just spaces."
    if len(username) > 20:
        return False, f"{filed} is too long. Maximum 20 characters allowed."
    if len(username) < 3:
        return False, f"{filed} is too short. Minimum 3 characters required."
    
    for char in username:

        if char.isdigit():
            return False, f"{filed} cannot contain numbers."

        if not char.isalnum():
            return False, f"{filed} cannot contain special characters or symbols. Found: '{char}'"
        
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

def validate_log_filter(raw_value, field_name):
    """
    Validates optional log filters (severity or event_type).
    Returns (True, cleaned_value) or (False, error_message).
    """

    # Define allowed choices to prevent bad database queries
    ALLOWED_SEVERITIES = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    ALLOWED_EVENT_TYPES = ["LOGIN_SUCCESS", "LOGIN_FAILURE", "SERVER_CRASH", "DATABASE_ERROR"]

    # 1. If the field wasn't sent, or is literally None, it's completely fine (it's optional)
    if raw_value is None:
        return True, None

    # 2. Convert to string and strip accidental spacing
    cleaned_value = str(raw_value).strip()

    # 3. If it's an empty string after stripping, treat it as None (skip filtering)
    if cleaned_value == "":
        return True, None

    # 4. Check against allowed choices depending on the field name
    if field_name.lower() == "severity":
        # Uppercase it automatically so 'critical' becomes 'CRITICAL'
        cleaned_value = cleaned_value.upper()
        if cleaned_value not in ALLOWED_SEVERITIES:
            return False, f"Invalid severity choice: '{cleaned_value}'. Allowed options are: {', '.join(ALLOWED_SEVERITIES)}"

    elif field_name.lower() == "event_type":
        cleaned_value = cleaned_value.upper()
        if cleaned_value not in ALLOWED_EVENT_TYPES:
            return False, f"Invalid event_type choice: '{cleaned_value}'. Allowed options are: {', '.join(ALLOWED_EVENT_TYPES)}"

    # Everything looks good!
    return True, cleaned_value

def get_event_types_for_app(raw_app_name):
    """
    Takes an application name (e.g., 'github') and returns a list of 
    matching database event_types, or None if the filter shouldn't be applied.
    """
    if raw_app_name is None:
        return True, None

    # Clean the input string
    app_name = str(raw_app_name).strip().lower()

    if app_name == "":
        return True, None

    # Define our application map based on actual event types saved by webhook views
    APP_MAP = {
        "github": [
            "CODE_PUSH", "PULL_REQUEST_OPENED", "PULL_REQUEST_CLOSED",
            "PULL_REQUEST_MERGED", "ISSUE_OPENED", "ISSUE_CLOSED",
            "REPO_STARRED",
        ],
        "slack": [
            "SLACK_MESSAGE", "SLACK_MEMBER_JOINED",
            "SLACK_REACTION", "SLACK_CHANNEL_CREATED",
        ],
        "jira": [
            "JIRA_ISSUE_CREATED", "JIRA_ISSUE_UPDATED",
            "JIRA_COMMENT_CREATED",
        ],
    }

    # Check if the requested application exists in our mapping
    if app_name in APP_MAP:
        return True, APP_MAP[app_name]
    else:
        # User typed something weird like "instagram"
        return False, f"Invalid application search: '{raw_app_name}'. Choose from github, slack, or jira."


def validate_date_filters(start_date_raw, end_date_raw):
    """
    Validates and formats optional start and end dates.
    Expects format: 'YYYY-MM-DD'
    Returns: (is_valid, cleaned_start_date, cleaned_end_date) or (False, error_msg, None)
    """
    cleaned_start = None
    cleaned_end = None

    # 1. Clean and parse Start Date if provided
    if start_date_raw:
        start_str = str(start_date_raw).strip()
        if start_str != "":
            try:
                # Convert string 'YYYY-MM-DD' into a datetime object (defaults to 00:00:00 midnight)
                cleaned_start = datetime.strptime(start_str, "%Y-%m-%d")
            except ValueError:
                return False, "Invalid start_date format. Use YYYY-MM-DD (e.g., 2026-06-15)", None

    # 2. Clean and parse End Date if provided
    if end_date_raw:
        end_str = str(end_date_raw).strip()
        if end_str != "":
            try:
                parsed_end = datetime.strptime(end_str, "%Y-%m-%d")
                # Fix the "Time Bomb": set time to the very last microsecond of that day
                cleaned_end = datetime.combine(parsed_end.date(), time.max)
            except ValueError:
                return False, "Invalid end_date format. Use YYYY-MM-DD (e.g., 2026-06-16)", None

    # 3. Logic Check: Ensure Start Date isn't AFTER the End Date
    if cleaned_start and cleaned_end:
        if cleaned_start > cleaned_end:
            return False, "Start date cannot be after the end date.", None

    # Validation succeeded! Return True along with both cleaned objects
    return True, cleaned_start, cleaned_end