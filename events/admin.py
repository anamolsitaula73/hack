from django.contrib import admin
from .models import Event

class EventAdmin(admin.ModelAdmin):
    list_display = ('event_type', 'event_date', 'location', 'number_of_people', 'event_budget', 'created_by')
    list_filter = ('event_type', 'event_date', 'location', 'created_by')
    search_fields = ('event_type', 'location', 'created_by__username')
    date_hierarchy = 'event_date'
    ordering = ('-event_date',)

admin.site.register(Event, EventAdmin)
