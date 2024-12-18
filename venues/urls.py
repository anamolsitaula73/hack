# venues/urls.py
from django.urls import path,include
from . import views

urlpatterns = [
    path('register/', views.register_venue, name='register_venue'),
    path('', views.venue_list, name='venue_list'),
    path('venue/<int:venue_id>/add_package/', views.add_pricing_package, name='add_pricing_package'),
    
]
