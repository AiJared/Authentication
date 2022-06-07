from wsgiref import validate
from rest_framework import serializers
from accounts.models import Administrator, Student, User
from django.core.exceptions import ObjectDoesNotExist
from rest_framework_simplejwt.serializers import TokenObtaibPairSerializer
from rest_framework_simplejwt.settings import api_settings
from django.contrib.auth.models import update_last_login
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import DjangoUnicodeDecodeError, force_str, smart_bytes, smart_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework.exceptions import AuthenticationFailed


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "email", "full_name", "phone", "timestamp")
        read_only_fields = ("id", "timestamp")

class LoginSerializer(TokenObtaibPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = self.get_token(self.user)
        data["user"] = UserSerializer(self.user).data
        data["refresh"] = str(refresh)
        data["access"] = str(refresh.access_token)

        if api_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)
        return data

class StudentRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=30, min_length=8, 
        write_only=True, required=True
    )
    email = serializers.EmailField(
        max_length=130, required=True
    )

    class Meta:
        model = User
        fields = ("username", 
                "email", "phone", "password")
        def create(self, validated_data):
            try:
                user = User.objects.get(email=validated_data['email'])
            except ObjectDoesNotExist:
                if(validated_data["role"] == "Student"):
                    user = User.objects.create(
                        username=validated_data["username"],
                        email=validated_data["email"],
                        phone=validated_data["phone"],
                        is_active = False,
                        role="student"
                    )
                    user.set_password(validated_data["password"])
                    user.save()
                return user

class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(
        max_length=155, min_length=8
    )

    class Meta:
        fields = ['email',]
    
    def validate(self, attrs):
        return attrs

class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=8, max_length=30, write_only=True)
    password_confirmation = serializers.CharField(
        min_length=8, max_length=30, write_only=True
    )
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(
        min_length=1, write_only=True
    )

    class Meta:
        fields = ("password", "password_confirmation", "token", "uidb64")


class StudentProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Student
        fields = ("id", "institution", "school", "department",
                    "course", "year", "county", "town"
                    "address", "postal_code")

