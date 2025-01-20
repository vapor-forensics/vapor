from django.db import models
from apps.aws.models import AWSAccount
from apps.case.models import Case
from django.contrib.postgres.indexes import BTreeIndex

class NormalizedLog(models.Model):
    SOURCE = [
        ("aws", "Amazon Web Services"),
        ("gcp", "Google Cloud Platform"),
        ("azure", "Microsoft Azure"),
    ]

    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='normalized_logs')
    log_id = models.CharField(max_length=255, blank=True, null=True)  # Log ID from the service
    log_source = models.CharField(max_length=50, choices=SOURCE, db_index=True)  # Indexed
    log_type = models.CharField(max_length=100, db_index=True)  # Indexed
    event_name = models.CharField(max_length=255, db_index=True)  # Indexed
    event_time = models.DateTimeField(db_index=True)  # Indexed for date filtering
    user_identity = models.CharField(max_length=255, blank=True, null=True)  # Stores username or user info
    ip_address = models.GenericIPAddressField(blank=True, null=True, db_index=True)  # Indexed
    resources = models.TextField(blank=True, null=True)  # Serialized list of resources as text
    raw_data = models.TextField()  # Serialized JSON as text
    extra_data = models.TextField(blank=True, null=True)  # Serialized additional metadata as text

    # Relationships
    aws_account = models.ForeignKey(AWSAccount, on_delete=models.CASCADE, related_name='normalized_logs')

    # Utility
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)  # Indexed for sorting by creation time

    def __str__(self):
        return f"{self.event_name} ({self.log_source}) - Case {self.case.name}"

    class Meta:
        indexes = [
            BTreeIndex(fields=["log_source"]),
            BTreeIndex(fields=["log_type"]),
            BTreeIndex(fields=["event_name"]),
            BTreeIndex(fields=["event_time"]),
            BTreeIndex(fields=["ip_address"]),
        ]
