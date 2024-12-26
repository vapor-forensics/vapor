import uuid
from django.db import models
from django.conf import settings
from django.utils.text import slugify

class Case(models.Model):

    STATUS = [

    ("investigating", "Investigating"),
    ("closed", "Closed"),


    ]
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    slug = models.SlugField(max_length=255, unique=True, blank=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=100, choices=STATUS, null=True, blank=True)

    # Utility
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Relationships
    users = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name="cases")
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="created_cases")

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.name} ({self.uuid})"

