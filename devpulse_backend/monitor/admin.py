from django.contrib import admin
from .models import Integration,ActivityLog,SystemAlert

# Register your models here.
@admin.register(Integration)
class IntigrationAdmin(admin.ModelAdmin):
    list_display=("name","platform_type","is_active","created_at")
    list_filter=("platform_type", "is_active")
    readonly_fields=("id","created_at")


@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ("event_type", "severity", "integration", "created_at")
    list_filter = ("severity", "integration__platform_type")
    readonly_fields = ("id", "created_at")

@admin.register(SystemAlert)
class SystemAlertAdmin(admin.ModelAdmin):
    list_display = ("activity_log", "is_resolved", "resolved_at")
    list_filter = ("is_resolved",)
    readonly_fields = ("id",)