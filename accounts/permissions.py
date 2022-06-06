from rest_framework.permissions import SAFE_METHODS, BasePermission

class IsStudent(BasePermission):
    def has_permission(self, request, view):
        if request.user.is_authentcated:
            return True
        
    def has_object_permission(self, request, view, obj):
        if request.user.role == "student":
            return True
        if request.method in SAFE_METHODS:
            return True
        return False

class IsAdministrator(BasePermission):
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            return True
    
    def has_object_permission(self, request, view, obj):
        if (request.user.role == "Administrator" or
            request.user.is_admin or
            request.user.is_staff):
            return True
        if request.method in SAFE_METHODS:
            return True
        return False