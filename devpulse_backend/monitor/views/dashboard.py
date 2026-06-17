from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from monitor.models import ActivityLog,Integration
from monitor.serializers import ActivityLogSerializer

# ============================================================
# VIEW 1: Get History Logs
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
# VIEW 1B: Dashboard History (no auth needed — used by the HTML page)
# URL: GET /api/v1/dashboard/history/
# ============================================================
class DashboardHistoryView(APIView):
    """
    Returns the last 50 logs in the SAME format as the WebSocket signal,
    so the dashboard can display them on page load.
    No authentication required because the dashboard page itself has no login.
    """
    
    permission_classes = [AllowAny]
    authentication_classes = []

    def get(self, request):
        try:
            logs = ActivityLog.objects.select_related("integration").order_by("-created_at")[:50]

            results = []
            for log in logs:
                results.append({
                    "event_type": log.event_type,
                    "severity": log.severity,
                    "message": log.payload.get("message", "No message"),
                    "integration": log.integration.name,
                    "repo_name": log.payload.get("repo_name", log.integration.name),
                    "timestamp": log.created_at.isoformat(),
                })

            return Response({"data": results}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": "error",
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# ============================================================
# VIEW  2: Receive Webhook Data
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
        
