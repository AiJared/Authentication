from django.contrib import admin
from django.contrib.auth.models import Group
from accounts.models import Administrator, Student, User

admin.site.unregister(Group)

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    search_fields = ['email', 'username']
    list_display = ("username", "email", "role",
                    "phone", "is_active", "is_admin",
                    "is_staff", "timestamp")
    list_filter = ("is_active", "is_admin", "is_staff", "role")


@admin.register(Administrator)
class AdministratorAdmin(admin.ModelAdmin):
    search_fields = ['get_username',]
    list_display = ("get_username", "county", "town", "estate")

    def get_username(self, obj):
        return obj.user.username
    get_username.short_description = "Username"
    get_username.admin_order_field = "user__username"

@admin.register(Student)
class StudentAdmin(admin.ModelAdmin):
    search_fields = ["get_username",]
    list_display = ("get_username", "institution",
                    "school", "department", "course",
                    "year", "county", "town", "address",
                    "postal_code")
    
    def get_username(self, obj):
        return obj.user.username
    get_username.short_description = "Username"
    get_username.admin_order_field = "user__username"