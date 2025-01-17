from django.db import models
from apps.aws.models import AWSResource
from apps.case.models import Case

# Create your models here.

# This stores all the logs in a normalised fashion. All logs from all services are normalized to allow for standard queries
class NormalizedLog(models.Model):
    SOURCE = [
        ("aws", "Amazon Web Services"),
        ("gcp", "Google Cloud Platform"),
        ("azure", "Microsoft Azure"),
    ]

    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='normalized_logs')
    log_id = models.CharField(max_length=255, blank=True, null=True) # Log id from the service
    log_source = models.CharField(max_length=50, choices=SOURCE)
    log_type = models.CharField(max_length=100)
    event_name = models.CharField(max_length=255)
    event_time = models.DateTimeField()
    user_identity = models.JSONField(blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    resources = models.JSONField(blank=True, null=True)
    raw_data = models.JSONField()
    extra_data = models.JSONField(blank=True, null=True)

    # Relationships
    aws_resources = models.ManyToManyField(AWSResource, related_name='normalized_logs')

    # Utility
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.event_name} ({self.log_source}) - Case {self.case.name}"


