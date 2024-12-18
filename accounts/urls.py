# accounts/urls.py
from django.urls import path,include
from .views import (signup_view, login_view, logout_view, 
                    home_view, verify_otp_view, resend_otp_view,
                    user_pricing_packages,booked_venues,cancel_booking,my_profile,
                    CustomPasswordChangeView,update_name,AboutUsView)


urlpatterns = [
    path('signup/', signup_view, name='signup'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('', home_view, name='home'),
    path('', include('venues.urls')), 
    path('', include('owner.urls')), 
    path('verify-otp/', verify_otp_view, name='verify_otp'),
    path('resend-otp/', resend_otp_view, name='resend_otp'),
    path('owner/<int:venue_id>/', user_pricing_packages, name='user_pricing_packages'),
    path('accounts/', include('django.contrib.auth.urls')),
    path('booked/', booked_venues, name='booked_venues'),
    path('cancel_booking/<int:booking_id>/', cancel_booking, name='cancel_booking'),
    path('my-profile/', my_profile, name='my-profile'),
    path('my-profile/', CustomPasswordChangeView.as_view(), name='password_change'),
    path('update_name/', update_name, name='update_name'),
    
    path('about/', AboutUsView.as_view(), name='about_us'),

]
