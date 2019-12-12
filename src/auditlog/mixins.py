import json
from django.utils.html import mark_safe
import datetime
from django.conf import settings
from .middleware import AuditlogMiddleware
import threading
import time
import requests
from auditlog.models import LogEntry
import pytz


try:
    from django.core import urlresolvers
except ImportError:
    from django import urls as urlresolvers
try:
    from django.urls.exceptions import NoReverseMatch
except ImportError:
    from django.core.urlresolvers import NoReverseMatch
try:
    from django.utils.deprecation import MiddlewareMixin
except ImportError:
    MiddlewareMixin = object

MAX = 75

threadlocal = threading.local()

class MiddlewareMixinclass(MiddlewareMixin):
    def disp_remote_addr(self,obj):
        return obj.remote_addr
    disp_remote_addr.short_description = "IP Address"

class LogEntryAdminMixin(object):

    #GEOIP API used to get user location details.
    headers = {
        'accept': "application/json",
        'content-type': "application/json"
        }
    response = requests.request("GET", settings.AUDITLOG_GOIP_API, headers=headers)
    response_dict = json.loads(response.text)       #converting response to dictionary
    tz_from_response = response_dict["time_zone"]

    def created(self, obj):
        new_ts = obj.timestamp.strftime("%m/%d/%Y %I:%M %p")
        new_ts = obj.timestamp.strptime(new_ts,"%m/%d/%Y %I:%M %p")
        system_tz = pytz.timezone(settings.TIME_ZONE)
        local_tz = pytz.timezone(LogEntryAdminMixin.tz_from_response)       #local tz set as timezone from response
        local_ts = system_tz.localize(new_ts).astimezone(local_tz)      #returns datetime in the local timezone
        local_ts = local_ts.strftime("%m/%d/%Y %I:%M %p")
        return local_ts
    created.short_description = 'Date'

    def entity_type(self,obj):
        #entity type for KLC objects
        if obj.content_type_id == 0:
            return "N/A"
        if obj.content_type_id == 8 or obj.content_type_id == 9:   #Displays client for all models inside it
            return "client"
        if obj.content_type_id == 90 or obj.content_type_id == 10:    #Displays user for all models inside it
            return "user"
        
        return obj.content_type.model
    entity_type.short_description = "Entity type"

    def user_url(self, obj):
        if obj.actor:
            app_label, model = settings.AUTH_USER_MODEL.split('.')
            viewname = 'admin:%s_%s_change' % (app_label, model.lower())
            try:
                link = urlresolvers.reverse(viewname, args=[obj.actor.id])
            except NoReverseMatch:
                return (obj.actor)
            return ( obj.actor)
        return (obj.object_repr)  #Previously returned system ,now changed to return object_repr(username) to display username in last_login entries
    user_url.allow_tags = True      #Returns user whose last_login is changed which is the username itself.
    user_url.short_description = 'User'

    def resource_url(self, obj):
        app_label, model = obj.content_type.app_label, obj.content_type.model
        viewname = 'admin:%s_%s_change' % (app_label, model)
        try:
            args = [obj.object_pk] if obj.object_id is None else [obj.object_id]
            link = urlresolvers.reverse(viewname, args=args)
        except NoReverseMatch:
            obj_store = obj.object_repr
            return obj.object_repr
        else:
            obj_store = str(obj.object_repr)
            return (obj.object_repr)
    resource_url.allow_tags = True
    resource_url.short_description = 'Entity name'

    def msg_short(self, obj):
        if obj.action == 2:
            return 'Deleted object'  # delete
        if obj.action == 3 or obj.action == 4 or obj.action == 1 and obj.content_type_id == 108 and obj.additional_data == "Client_name":     #to display changes for actions of download-3,KLC-4
            return obj.changes                                                                       #and also when update action-1 is done for client name in Client Group
        changes = json.loads(obj.changes)
        s = '' if len(changes) == 1 else 's'
        fields = ', '.join(changes.keys())
        if len(fields) > MAX:
            i = fields.rfind(' ', 0, MAX)
            fields = fields[:i] + ' ..'
        return '%d change%s: %s' % (len(changes), s, fields)
    msg_short.short_description = 'Description'

    def msg(self, obj):
        if obj.action == 2:
            return ''  # delete
        changes = json.loads(obj.changes)
        msg = '<table><tr><th>No.</th><th>Field</th><th>From</th><th>To</th></tr>'
        for i, field in enumerate(sorted(changes), 1):
            value = [i, field] + (['***', '***'] if field == 'password' or field == 'kaseya_password' or field == 'webroot_password' or field == 'db_password' or field == 'nlm_server_password' else changes[field]) #to display values of password fields as **** 
            #changes for last_login field in logging entries
            if field == 'last_login':
                    for i in range(len(changes[field])):    #iterating list
                        system_tz = pytz.timezone(settings.TIME_ZONE)
                        local_tz = pytz.timezone(LogEntryAdminMixin.tz_from_response)       #local tz set as timezone from response
                        ologin_date = changes[field][0]     #storing value at index 0 as old login date
                        ologin_date = datetime.datetime.strptime(ologin_date, "%Y-%m-%d %H:%M:%S.%f")       #from str to dt obj
                        local_ologin_date = system_tz.localize(ologin_date).astimezone(local_tz)      #returns datetime in the local timezone
                        local_ologin_date = local_ologin_date.strftime("%m/%d/%Y %I:%M %p")     #converting date into string type
                        nlogin_date = changes[field][1]     #storing value at index 0 as old login date
                        nlogin_date = datetime.datetime.strptime(nlogin_date, "%Y-%m-%d %H:%M:%S.%f")       #from str to dt obj
                        local_nlogin_date = system_tz.localize(nlogin_date).astimezone(local_tz)      #returns datetime in the local timezone
                        local_nlogin_date = local_nlogin_date.strftime("%m/%d/%Y %I:%M %p")    #converting date into string type          
                        value = [i,field] + [local_ologin_date,local_nlogin_date]
            msg += '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % tuple(value)
        msg += '</table>'
        return mark_safe(msg)       #mark_safe is used to return html code in Python
    msg.allow_tags = True
    msg.short_description = 'Changes'
