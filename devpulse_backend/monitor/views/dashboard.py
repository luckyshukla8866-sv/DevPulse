from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from monitor.models import ActivityLog,Integration
from monitor.serializers import ActivityLogSerializer
from monitor.validations import validate_log_filter,get_event_types_for_app,validate_date_filters
from rest_framework.pagination import PageNumberPagination
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
            
            severity_valid, severity_result=validate_log_filter(severity, "severity")
            event_valid, event_result = validate_log_filter(event_type,"event_type")

            
            if not severity_valid:
                return Response({
                    "status": "error", 
                    "message": severity_result
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            if not event_valid:
                return Response({
                    "status": "error", 
                    "message": event_result
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            if severity:
                logs=logs.filter(severity=severity)
            
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
        
class SearchView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # 1. Grab raw values from request bod
            raw_app = request.data.get("application")
            raw_start = request.data.get("start_date")
            raw_end = request.data.get("end_date")

            #Run validations
            is_valid, app_result = get_event_types_for_app(raw_app)
            is_valid_date, error_or_start, cleaned_end = validate_date_filters(raw_start, raw_end)

            # Handle validation failures early
            if not is_valid:
                return Response({
                    "status": "error",
                    "message": app_result,
                    },status=status.HTTP_400_BAD_REQUEST)
            
            if not is_valid_date:
                # If validation failed, the second returned item is our error string
                return Response({
                    "status": "error",
                    "message": error_or_start
                 },status=status.HTTP_400_BAD_REQUEST)
            
            logs = ActivityLog.objects.all().order_by("-created_at")

         
            if app_result is not None:
                # If app_result is ['REPO_STARRED'], this restricts queries to GitHub only
                logs = logs.filter(event_type__in=app_result)
            
            # If valid, unpack the cleaned dates safely
            cleaned_start = error_or_start

            # Apply Date Filters conditionally based on what the user provided
            if cleaned_start:
                # 'created_at__gte' means: created_at >= cleaned_start
                logs = logs.filter(created_at__gte=cleaned_start)

            if cleaned_end:
                # 'created_at__lte' means: created_at <= cleaned_end
                logs = logs.filter(created_at__lte=cleaned_end)

            
            # =========================================================
            # 6. PAGINATION LOGIC DROPPED IN HERE
            # =========================================================
            paginator = PageNumberPagination()
            # Set how many logs you want to see per page (e.g., 10 records)
            paginator.page_size = 10  
            
            # This slices the QuerySet dynamically based on the '?page=' query parameter
            paginated_logs = paginator.paginate_queryset(logs, request, view=self)
            
            # 7. Serialize only the paginated subset of records
            serializer = ActivityLogSerializer(paginated_logs, many=True)
            
            return Response({
                "status": "success",
                "message": "Data fetched successfully",
                "count": paginator.page.paginator.count,
                "next": paginator.get_next_link(),
                "previous": paginator.get_previous_link(),
                "data": serializer.data,
            })

        except Exception as e:
            return Response({
                "status": "error", 
                "message": str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============================================================
# VIEW 4: Dashboard Search (no auth — used by the HTML page)
# URL: GET /api/v1/dashboard/search/?application=github&start_date=2026-06-01&end_date=2026-06-19
# ============================================================
class DashboardSearchView(APIView):
    """
    Searches logs by application name and date range.
    No authentication — the dashboard page calls this directly.
    Returns data in the same format as DashboardHistoryView.
    """
    permission_classes = [AllowAny]
    authentication_classes = []

    def get(self, request):
        try:
            # 1. Read filters from URL query params 
            raw_app = request.query_params.get("application")
            raw_start = request.query_params.get("start_date")
            raw_event_type = request.query_params.get("event_type")
            raw_end = request.query_params.get("end_date")

            # 2. Validate application name
            is_valid, app_result = get_event_types_for_app(raw_app)
            if not is_valid:
                return Response({
                    "status": "error",
                    "message": app_result,
                }, status=status.HTTP_400_BAD_REQUEST)

            # 3. Validate date filters
            is_valid_date, error_or_start, cleaned_end = validate_date_filters(raw_start, raw_end)
            if not is_valid_date:
                return Response({
                    "status": "error",
                    "message": error_or_start,
                }, status=status.HTTP_400_BAD_REQUEST)

            # 4. Start with all logs, newest first
            logs = ActivityLog.objects.select_related("integration").order_by("-created_at")

            # 5. Filter by application (event types)
            if raw_event_type:
                logs = logs.filter(event_type=raw_event_type)   
            if app_result is not None:
                logs = logs.filter(event_type__in=app_result)

            # 6. Filter by date range
            cleaned_start = error_or_start
            if cleaned_start:
                logs = logs.filter(created_at__gte=cleaned_start)
            if cleaned_end:
                logs = logs.filter(created_at__lte=cleaned_end)

            # 7. PAGINATION — slice into pages of 10
            paginator = PageNumberPagination()
            paginator.page_size = 10

            try:
                paginated_logs = paginator.paginate_queryset(logs, request, view=self)
            except Exception:
                return Response({
                    "status": "error",
                    "message": "Invalid page number.",
                }, status=status.HTTP_404_NOT_FOUND)

            # 8. Build response from ONLY this page's logs
            results = []
            for log in paginated_logs:
                results.append({
                    "event_type": log.event_type,
                    "severity": log.severity,
                    "message": log.payload.get("message", "No message"),
                    "integration": log.integration.name,
                    "repo_name": log.payload.get("repo_name", log.integration.name),
                    "timestamp": log.created_at.isoformat(),
                })

            return Response({
                "count": paginator.page.paginator.count,
                "next": paginator.get_next_link(),
                "previous": paginator.get_previous_link(),
                "data": results,
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": "error",
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)