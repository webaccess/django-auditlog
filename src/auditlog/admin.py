from django.contrib import admin
from .models import LogEntry
from .mixins import LogEntryAdminMixin
from .mixins import MiddlewareMixinclass
from .filters import ResourceTypeFilter
from .middleware import AuditlogMiddleware


class LogEntryAdmin(admin.ModelAdmin, LogEntryAdminMixin,MiddlewareMixinclass):
    list_display = ['created','user_url','action','entity_type','object_repr','msg_short','remote_addr']
    search_fields = ['changes','remote_addr','object_repr']
    list_filter = ['action',ResourceTypeFilter,'timestamp']
    readonly_fields = ['created', 'resource_url', 'action', 'user_url', 'msg']
    fieldsets = [
        (None, {'fields': ['created', 'user_url', 'resource_url']}),
        ('Changes', {'fields': ['action', 'msg']}),
    ]

    def has_add_permission(self, request):   # remove "add" permission
        return False

admin.site.register(LogEntry, LogEntryAdmin)
