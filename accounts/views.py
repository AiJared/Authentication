import jwt
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.core.files.base import File
from django.core.mail import BadHeaderError, EmailMessage, send_mail
from django.db.models import Q, query
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
from django.utils.encoding import (DjangoUnicodeDecodeError, force_bytes,
                                    force_str, force_text, smart_bytes,
                                    smart_str)
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.views.decorators.cache import never_cache
from django.views.generic import CreateView
from rest_framework import generics, serializers, status, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import (TokenObtainPairView,
                                            TokenRefreshView)


from accounts.models import (
    Administrator, Student, User
)
from accounts.permissions import (
    IsAdministrator, IsStudent)
from accounts.serializers import (
    LoginSerializer, UserSerializer,
    StudentRegistrationSerializer, ResetPasswordEmailRequestSerializer,
    SetNewPasswordSerializer, AdministratorProfileSerializer,
    StudentProfileSerializer)
from accounts.sendMails import (
    send_activation_mail, send_password_reset_mail)

class LoginViewSet(ModelViewSet, TokenObtainPairView):
    """
    User Login API VIew
    """
    serializer_class = LoginSerializer
    permission_classes = (AllowAny,)
    http_method_names = ["post"]


    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])
        return Response(serializer.validated_data,
                        status=status.HTTP_200_OK)
    
class RegistrationViewSet(ModelViewSet, TokenObtainPairView):
    """
    Student Registration API View
    """
    serializer_class = StudentRegistrationSerializer
    permission_classes = (AllowAny,)
    http_method_names = ["post"]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        user_data = serializer.data
        send_activation_mail(user_data, request)
        refresh = RefreshToken.for_user(user)
        res = {
            "refresh": str(refresh),
            "access": str(refresh.access_token)
        }
        return Response({
            "user": serializer.data,
            "refresh":res["access"],
            "token": res["access"]
        }, status=status.HTTP_201_CREATED)

class RefreshViewSet(viewsets.ViewSet, TokenRefreshView):
    """
    User Refresh Token API View
    """
    permission_classes = (AllowAny,)
    http_method_names = ["post"]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        return Response(serializer.validates_data, status=status.HTTP_200_OK)

def VerifyMail(request):
    token = request.GET.get('token')
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms='HS256',

        )
        user = User.objects.get(
            id=payload['user_id']
        )
        if not user.is_active:
            user.is_active = True
            user.save()
            messages.success(request, 
                            "Account was Successfully Verified.")
        else:
            messages.info(request,
                            """
                            Your account has already been activated.
                            You can now login.""")
    except jwt.ExpiredSignatureError as identifier:
        messages.warning(request,
                        "The Activation Link has Expired. Please request another another.")
    except jwt.exceptions.DecodeError as identifier:
        messages.warning(request, "Invalid Activation Link!")
    
    #context = {}
    #return render(request, "accounts/verify.html", context)

# Password Reset
class RequestPasswordResetEmail(ModelViewSet):
    """
    Password Reset API View
    The user input the email for password reset 
    """
    serializer_class = ResetPasswordEmailRequestSerializer
    permission_classes = (AllowAny,)
    http_method_name = ["post",]
    
    def create(self, request, *args, **kwargs):
        self.get_serializer(data=request.data)
        email = request.data["email"]
        if User.objects.get(email=email):
            user = User.objects.get(email=email)
            if user.is_active:
                send_password_reset_mail(user, request)
            return Response(
                {"Success": "We have emailed you a link to reset your password"},
                status=status.HTTP_200_OK
                )
        return Response({"Success": "Password Reset Link wa sent to your email."})

def PasswordResetTokenCheck(request, uidb64, token):
    try:
        id = smart_bytes(urlsafe_base64_decode(uidb64))
        user = User.objects.get(id=id)
        if not PasswordResetTokenGenerator().check_token(user, token):
            messages.info(
                request,
                "Password Reset Link is no longer valid, Please request a new one.")
    except DjangoUnicodeDecodeError as identifier:
        if not PasswordResetTokenGenerator().check_token(user, token):
            messages.info(
                request,
                "Password in no longer valid, please request a new one.")
    #context = {
    #   "uidb64": uidb64,
    #   "token": token,
    # }
    #return render(request, "accounts/passwors_reset.html", context)