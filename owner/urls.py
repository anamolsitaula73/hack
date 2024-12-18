# venues/urls.py
from django.urls import path
from .views import (
    venue_owner_signup, login_view, home_view, venue_detail,
    owner_pricing_packages, owner_add_pricing_package,
    delete_package, edit_package, user_packages, edit_venue,book_venue,show_routes,
    booking_success,view_bookings,cancel_owner_booking,edit_venue_image,confirm_booking,check_out_booking,show_owner_route,update_location,
    AboutUsView, GetLatestLocationView
)

urlpatterns = [
    path('signup_owner/', venue_owner_signup, name='signup_owner'),
    path('login_owner/', login_view, name='login_owner'),
    path('home_owner/', home_view, name='home_owner'),
    path('', venue_detail, name='venue_detail'),
    path('owner/<int:venue_id>/', owner_pricing_packages, name='owner_pricing_packages'),

    path('owner/<int:venue_id>/delete/<int:package_id>/', delete_package, name='delete_package'),
    path('owner/<int:venue_id>/edit/<int:package_id>/', edit_package, name='edit_package'),

    path('owner_add_pricing_package/<int:venue_id>/', owner_add_pricing_package, name='owner_add_pricing_package'),
    path('owner_add_pricing_package/<int:venue_id>/add_package/', owner_add_pricing_package, name='add_pricing_package'),

    path('pricing_packages/<int:venue_id>/', user_packages, name='user_packages'),
    path('owner/<int:pk>/edit-venue/', edit_venue, name='edit_venue'),

    path('book/<int:venue_id>/', book_venue, name='book_venue'),
    path('booking_success/<int:booking_id>/', booking_success, name='booking_success'),

    path('view_bookings/<int:venue_id>/', view_bookings, name='view_bookings'),
    path('cancel_owner_booking/<int:booking_id>/', cancel_owner_booking, name='cancel_owner_booking'),

    path('confirm_booking/<int:booking_id>/', confirm_booking, name='confirm_booking'),
    path('check_out_booking/<int:booking_id>/', check_out_booking, name='check_out_booking'),

    path('edit_venue_image/<int:venue_id>/', edit_venue_image, name='edit_venue_image'),

    path('aboutus/', AboutUsView.as_view(), name='about_us_home'),
    path('show_owner_route/', show_owner_route, name='show_owner_route'),
    
    path('api/get-latest-location/', GetLatestLocationView.as_view(), name='get-latest-location'),
    path('update-location/', update_location, name='update_location'),
    # path('api/update-location/', update_location, name='update_location'),



    


    
]
