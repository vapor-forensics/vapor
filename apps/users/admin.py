from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import CustomUser


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    list_display = UserAdmin.list_display + ("date_joined",)
    list_filter = UserAdmin.list_filter + ("date_joined",)
    ordering = ("-date_joined",)

    fieldsets = UserAdmin.fieldsets + (("Custom Fields", {"fields": ("avatar",)}),)
