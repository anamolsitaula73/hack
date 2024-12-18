# events/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('create/', views.create_event, name='create_event'),
    path('', views.event_list, name='event_list'),
    path('events/<int:event_id>/recommend/', views.recommend_venues, name='recommend_venue'),
     path('delete_event/<int:event_id>/', views.delete_event, name='delete_event'),
]
