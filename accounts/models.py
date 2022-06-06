from django.db import models
from phonenumber_field.modelfields import PhoneNumberField
from django.contrib.auth import validators
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.utils.translation import gettext as _
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager

class TrackingModel(models.Model):
    date_created = models.DateTimeField(_("date created"), auto_now_add=True)
    date_updated = models.DateTimeField(_("date updated"), auto_now=True)

    class Meta:
        abstract = True

class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, password=None,
                    is_active=True, is_admin=False, is_staff=False
                    ):
        if email is None:
            raise ValueError("User must have an email!")
        if username is None:
            raise ValueError("User must have a username!")
        if password is None:
            raise ValueError("User must have a password!")
        
        user_obj = self.model(
            email = self.normalize_email(email),
            username = username
        )
        
        user_obj.set_password(password)
        user_obj.is_active = is_active
        user_obj.is_admin = is_admin
        user_obj.is_staff = is_staff

        user_obj.save(using=self._db)

        return user_obj

    def create_staff(self, email, username, password=None):
        user = self.create_user(
            email, username, password=password,
            is_active=True,
            is_admin=False,
            is_staff=False)

        return user
    
    def create_superuser(self, email,username, password=None):
        user = self.create_user(
            email, username, password=password,
            is_active=True,
            is_admin=True,
            is_staff=True
        )

        return user