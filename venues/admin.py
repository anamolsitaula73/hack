# venues/admin.py
from django.contrib import admin
from .models import Venue, PricingPackage

class PricingPackageInline(admin.TabularInline):
    model = PricingPackage
    extra = 1

class VenueAdmin(admin.ModelAdmin):
    list_display = ('name', 'address', 'contact_email')
    search_fields = ('name', 'address')
    inlines = [PricingPackageInline]

admin.site.register(Venue, VenueAdmin)
admin.site.register(PricingPackage)
