import datetime
from statistics import mean
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.utils.encoding import smart_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework.reverse import reverse
from rest_framework_simplejwt.tokens import RefreshToken

from accounts.models import User

def send_activation_mail(user_data, request):
    user = User.objects.get(email=user_data['email'])
    current_site = get_current_site(request).domain
    mail_subject = "Verify Your Acount"
    to_mail = user.email
    token = RefreshToken.for_user(user).access_token
    relativeLink = reverse('api:email-verify')
    absourl = "http://"+current_site+relativeLink+"?token="+str(token)
    message = f"""
Welcome to Portal,
Hi {user.username},
Click on the link below to verify your account,
{absourl}

This is an automatically generated email. Please do not reply.
@{datetime.date.tofay().year} Portal | Nairobi
    """
    email = EmailMessage(
        subject=mail_subject,
        body=message,
        to = [to_mail]
    )
    email.send()