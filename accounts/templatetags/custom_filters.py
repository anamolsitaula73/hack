# accounts/templatetags/custom_filters.py
from django import template
from datetime import date, datetime

register = template.Library()

@register.filter(name='is_expired')
def is_expired(booking):
    today_date = date.today()
    now = datetime.now().time()
    if booking.date < today_date or (booking.date == today_date and booking.time < now):
        return True
    return False
