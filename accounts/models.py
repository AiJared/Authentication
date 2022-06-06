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

