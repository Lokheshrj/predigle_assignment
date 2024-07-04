from rest_framework.permissions import BasePermission, IsAuthenticated

class IsAdminUserOnly(BasePermission):
    """
    Custom permission to allow only admin users to perform operations.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == 'admin'

class IsInstructorUserOnly(BasePermission):
    """
    Custom permission to allow only instructor users to perform operations.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == 'instructor'

class AndPermission(BasePermission):
    """
    Custom permission to combine multiple permissions with an AND condition.
    """
    def __init__(self, *perms):
        self.perms = perms

    def has_permission(self, request, view):
        return all(perm.has_permission(request, view) for perm in self.perms)
    def has_object_permission(self, request, view, obj):
        return all(perm.has_object_permission(request, view, obj) for perm in self.perms)
