# accounts/views.py
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .forms import SignUpForm, LoginForm, OTPForm
from django.shortcuts import render, get_object_or_404, redirect
from django.template.loader import render_to_string
from django.conf import settings
from django.contrib import messages
from django.core.mail import send_mail
from owner.models import Venue,Booking
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.generic import TemplateView

from datetime import date, datetime

from django.contrib.auth.views import PasswordChangeView
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_post_parameters




from .utils import generate_otp, send_otp_via_email
from .models import UserOTP  # We'll create this model to store OTPs
from django.urls import reverse
from django.core.cache import cache
from django.contrib.auth import get_user_model
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from .forms import UserUpdateForm

def signup_view(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')

            user = form.save(commit=False)
            user.is_active = False  # Deactivate account till it is verified
            user.save()
            
            otp = generate_otp()
            send_otp_via_email(user.email, otp)
            
            UserOTP.objects.create(user=user, otp=otp)  # Save OTP in database
            request.session['email'] = user.email
            request.session['username'] = username  # Store username in session

            return redirect(reverse('verify_otp'))
    else:
        form = SignUpForm()
    return render(request, 'accounts/signup.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                request.session['username'] = username  # Store username in session
                return redirect('/')
            else:
                messages.error(request, 'Invalid username or password.')
        else:
            messages.error(request, 'Invalid username or password.')
    else:
        form = LoginForm()
    return render(request, 'accounts/login.html', {'form': form})

def logout_view(request):
    logout(request)
    try:
        del request.session['username']  # Remove username from session
    except KeyError:
        pass
    return redirect('login')

# @login_required
def home_view(request):
    username = request.session.get('username', None)
    venues = Venue.objects.all()
    return render(request, 'accounts/home.html', {'username': username, 'venues': venues})



def verify_otp_view(request):
    if request.method == 'POST':
        form = OTPForm(request.POST)
        if form.is_valid():
            otp = form.cleaned_data.get('otp')
            username = request.session.get('username')
            try:
                user = User.objects.get(username=username)
                user_otp = UserOTP.objects.get(user=user)
                
                if user_otp.otp == otp:
                    user.is_active = True
                    user.save()
                    login(request, user)
                    messages.success(request, 'Your account has been verified.')
                    return redirect('/')
                else:
                    messages.error(request, 'Invalid OTP')
            except User.DoesNotExist:
                messages.error(request, 'User does not exist.')
            except UserOTP.DoesNotExist:
                messages.error(request, 'OTP does not exist.')
    else:
        form = OTPForm()
    
    return render(request, 'accounts/verify_otp.html', {'form': form})

def send_otp(email, otp):
    subject = 'Your OTP Code'
    message = f'Your OTP code is {otp}. It is valid for 10 minutes.'
    email_from = settings.DEFAULT_FROM_EMAIL
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)




User = get_user_model()    

def resend_otp_view(request):
    email = request.session.get('email')
    
    if email:
        # Generate a new OTP
        otp = generate_otp()
        cache.set(f'otp_{email}', otp, timeout=600)  # Store OTP in cache for 10 minutes

        # Update the OTP in the user's OTP record
        try:
            user = User.objects.get(email=email)
            user_otp, created = UserOTP.objects.get_or_create(user=user)
            user_otp.otp = otp
            user_otp.save()

            # Send the OTP via email
            send_otp_via_email(email, otp)
            messages.success(request, 'A new OTP has been sent to your email.')
        except User.DoesNotExist:
            messages.error(request, 'User does not exist.')
            return redirect('signup')
        except Exception as e:
            messages.error(request, f'Failed to send OTP: {e}')
            print(f'Error sending OTP: {e}')  # Debugging information
    else:
        messages.error(request, 'No email found in session. Please sign up again.')
        return redirect('signup')
    
    return redirect(reverse('verify_otp'))

      



    
def user_pricing_packages(request, venue_id):
    return render(request, 'owner/user_pricing_packages')




@login_required
def booked_venues(request):
    bookings = Booking.objects.filter(user=request.user).order_by('-id')

    today_date = date.today()
    now = datetime.now().time()

    def booking_is_expired(booking):
        if booking.date < today_date or (booking.date == today_date and booking.time < now):
            return True
        return False

    context = {
        'bookings': bookings,
        'booking_is_expired': booking_is_expired,
    }
    return render(request, 'accounts/booked_venues.html', context)



def cancel_booking(request, booking_id):
    booking = get_object_or_404(Booking, id=booking_id)
    user = booking.user
    venue = booking.venue
    
    if request.method == "POST":
        venue.occupancy -= booking.number_of_guests
        venue.save()
        booking.delete()
        

        # Send email to user
        subject_user = 'Booking Canceled'
        html_message_user = render_to_string('emails/booking_canceled_user.html', {
            'user': user,
            'venue': venue,
        })
        user_email = user.email
        send_mail(subject_user, None, settings.DEFAULT_FROM_EMAIL, [user_email], html_message=html_message_user)

        # Send email to venue owner
        subject_owner = 'Booking Canceled'
        html_message_owner = render_to_string('emails/booking_canceled_owner.html', {
            'venue': venue,
            'booking': booking,
        })
        owner_email = venue.contact_email
        send_mail(subject_owner, None, settings.DEFAULT_FROM_EMAIL, [owner_email], html_message=html_message_owner)

        return redirect('booked_venues')

    return render(request, 'owner/booked_venues.html', {'bookings': Booking.objects.all()})




@login_required
def my_profile(request):
    if request.method == 'POST':
        password_form = PasswordChangeForm(request.user, request.POST)
        if password_form.is_valid():
            user = password_form.save()
            update_session_auth_hash(request, user)  # Update session to prevent logout
            messages.success(request, 'Your password was successfully updated.')
            return redirect('my-profile')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        password_form = PasswordChangeForm(request.user)
    
    context = {
        'password_form': password_form,
    }
    return render(request, 'accounts/my_profile.html', context)






@method_decorator(sensitive_post_parameters('old_password', 'new_password1', 'new_password2'), name='dispatch')
class CustomPasswordChangeView(PasswordChangeView):
    template_name = 'accounts/password_change.html'  # Replace with your template name
    success_url = reverse_lazy('password_change_done')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.request.method == 'POST':
            # Clear old password field if there are form errors
            if context.get('form').errors:
                context['form'].fields['old_password'].initial = ''
        return context
    



@login_required
def update_name(request):
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        
        # Update user's first name and last name
        request.user.first_name = first_name
        request.user.last_name = last_name
        request.user.save()

        messages.success(request, 'Your name has been updated successfully.')
        return redirect('my-profile')  # Replace with your profile page URL name
    
    return render(request, 'accounts/my_profile.html')    



class AboutUsView(TemplateView):
    template_name = 'accounts/aboutus.html'