from django.contrib import admin
from .models import AWSAccount, AWSResource

# Register your models here.

admin.site.register(AWSAccount)
admin.site.register(AWSResource)