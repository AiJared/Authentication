from posixpath import basename
from accounts.views import (
                            AdministratorProfileAPIView, StudentProfileAPIView,
                            VerifyMail, RequestPasswordResetEmail, SetNewPasswordAPIView,
                            PasswordResetTokenCheck, LoginViewSet, RefreshViewSet, RegistrationViewSet
                            )
from django.contrib.auth import views as auth_views
from django.urls import path
from django.views.generic import TemplateView
from rest_framework.routers import SimpleRouter

app_name = "api"
routes = SimpleRouter()

routes.register('login', LoginViewSet, basename='login')
routes.register("signup", RegistrationViewSet,
                basename="registration")
routes.register('auth/refresh', RefreshViewSet,
                basename="auth_refresh")
routes.register('password-reset', RequestPasswordResetEmail,
                basename="requestPasswordReset")
routes.register('password-rest-complete', SetNewPasswordAPIView,
                basename="password-reset-complete")
# Profile
routes.register('student/profile', StudentProfileAPIView,
                basename="student-profile")
routes.register("admin/profile", AdministratorProfileAPIView,
                basename="admin-profile")

urlpatterns = [
    *routes.urls,
    path('activate/', VerifyMail, name="email-verification"),
    path("password-reset/<uidb64>/<token>/",
        PasswordResetTokenCheck,
        name="password-reset-token-check"),
    path('password-reset-successful/',
        TemplateView.as_view(
            template_name="accounts/password_reset_success.html"),
        name="passwordResetSuccess"
        )
]