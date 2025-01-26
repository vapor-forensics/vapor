from django.contrib import admin
from .models import AWSAccount, AWSResource, AWSLogSource, AWSCredential

# Register your models here.

admin.site.register(AWSAccount)
admin.site.register(AWSResource)
admin.site.register(AWSLogSource)
admin.site.register(AWSCredential)

