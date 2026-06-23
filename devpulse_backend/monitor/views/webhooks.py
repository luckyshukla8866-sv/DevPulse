from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from monitor.models import ActivityLog,Integration
import hashlib
import hmac


# ============================================================
# VIEW 1: Receive REAL GitHub Webhooks
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
            try:
                """
                Translates GitHub's event format to our event_type, severity, message.
                
                GitHub sends different JSON for each event type.
                This function reads the right fields from each type.
                """
                repo_name = data.get("repository", {}).get("name", "unknown-repo")

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
            except Exception as e:
                return Response({
                    "status": "error",
                    "message": str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
# ============================================================
# VIEW 2: Receive REAL Slack Events
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
        try:
            
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
            
        except Exception as e:
            return Response({
                "status": "error",
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# ============================================================
# VIEW 3: Receive REAL Jira Webhooks
# URL: POST /api/v1/webhooks/jira/<uuid:integration_id>/
# ============================================================

class JiraWebhookView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request, integration_id):
        try:
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
     
            # --- Translate Jira's format to our format ---
            event_type, severity, message = self.parse_jira_event(webhook_event, request.data)
      
            # --- Save to database ---
            payload = dict(request.data)
            payload["message"] = message
            print("******step1*****")
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

        except Exception as e:
            return Response({
                "status":"error",
                "message":str(e),
            },status=status.HTTP_500_INTERNAL_SERVER_ERROR) 
        
    def parse_jira_event(self, webhook_event, data):
        try:
            """
            Translates Jira's event format to our event_type, severity, message.
            """
           
            # Get common fields that most Jira events have
            user = (data.get("user") or {}).get("displayName", "Unknown")
            issue = data.get("issue", {})
            issue_key = issue.get("key", "")
            fields = issue.get("fields", {})
            summary = fields.get("summary", "No summary")
            priority = (fields.get("priority") or {}).get("name", "Normal")
            issue_type = (fields.get("issuetype") or{}).get("name", "Task")
    
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
        except Exception as e:
            return Response({
                "stauts":"error",
                "message":str(e)  
            },status=status.HTTP_500_INTERNAL_SERVER_ERROR)