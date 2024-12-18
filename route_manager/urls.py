from django.urls import path
from . import views  # Fixed import statement

urlpatterns = [
    path("login/", views.custom_login_view, name="login"),
    path('login/', views.route_manager_login, name='route_manager_login'),
    path('manager', views.route_manager_home, name='route_manager_home'),
    # path('api/create_route/', views.create_route, name='create_route'),
    # path('api/get_route/<int:route_id>/', views.get_route, name='get_route'),
    path('assign_route/<int:bus_id>/', views.assign_route_to_driver, name='assign_route_to_driver'),
    path('routes/', views.route_list, name='route_list'),  # Added route list
  
    path('save-route/', views.save_route, name='save_route'),
    path('', views.view_saved_routes, name='view_saved_routes'),
    path("logout/", views.logout_view, name="logout"),
    path('create-bus-stop/', views.create_bus_stop, name='create_bus_stop'),
    path('save_bus_stop/', views.save_bus_stop, name='save_bus_stop'),

    


]
