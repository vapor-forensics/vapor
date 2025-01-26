from django.contrib import admin
from .models import NormalizedLog, Tag

# Register your models here.

admin.site.register(NormalizedLog)
admin.site.register(Tag)