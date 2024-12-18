from django.contrib import admin
from .models import Route,BusStop

class RouteAdmin(admin.ModelAdmin):
    list_display = ('route_name', 'starting_point', 'destination', 'route_data')
    search_fields = ['route_name', 'starting_point', 'destination']
    list_filter = ['route_name', 'destination']
    
    # Make route_name the link to the detailed object
    list_display_links = ('route_name',)

    # Optionally add a route data preview
    def route_data_preview(self, obj):
        return str(obj.route_data)[:50]  # Display the first 50 characters of the route data
    route_data_preview.short_description = 'Route Data Preview'

admin.site.register(Route, RouteAdmin)


from django.contrib import admin
from .models import Route, BusStop

class BusStopAdmin(admin.ModelAdmin):
    # Fields to display in the list view
    list_display = ('id', 'name', 'latitude', 'longitude', 'route')  # Show bus stop id, name, lat/long, and associated route
    # Allow searching by name and route (via route name)
    search_fields = ('name', 'route__name')
    # Add filtering by route
    list_filter = ('route',)

    # Optionally add inlines for managing BusStops directly under the Route admin
    # Uncomment the following block if you want to allow editing BusStops within the Route admin page.
    # inlines = [BusStopInline]

# Register the BusStop model with custom admin interface
admin.site.register(BusStop, BusStopAdmin)

# Optionally, you can add an inline admin for BusStop within Route (if you need to manage them from the Route admin page)
class BusStopInline(admin.TabularInline):
    model = BusStop
    extra = 1  # Number of empty forms to display





