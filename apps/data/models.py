from django.db import models
from django.contrib.postgres.indexes import BTreeIndex


class Tag(models.Model):
    name = models.CharField(max_length=1000)
    description = models.TextField(blank=True, null=True)
    slug = models.SlugField(max_length=1000, unique=True)

    def __str__(self):
        return self.name

    @classmethod
    def init_tags(cls):
        tags = [
            {"name": "Suspicious", "slug": "suspicious"},
            {"name": "Malicious", "slug": "malicious"},
            {"name": "Informational", "slug": "informational"},
            {"name": "Follow-up", "slug": "follow-up"},
            {"name": "Low", "slug": "low"},
            {"name": "Medium", "slug": "medium"},
            {"name": "High", "slug": "high"},
        ]
        for tag in tags:
            cls.objects.get_or_create(name=tag["name"], slug=tag["slug"])


class NormalizedLog(models.Model):
    SOURCE = [
        ("aws", "Amazon Web Services"),
        ("gcp", "Google Cloud Platform"),
        ("azure", "Microsoft Azure"),
    ]

    case = models.ForeignKey('case.Case', on_delete=models.CASCADE, related_name='normalized_logs')
    file_name = models.CharField(max_length=2000, blank=True, null=True)
    event_id = models.CharField(max_length=1000, blank=True, null=True)  # Log ID from the service
    event_time = models.DateTimeField(db_index=True, null=True, blank=True)  # Indexed for date filtering
    event_source = models.CharField(max_length=1000, choices=SOURCE, null=True, blank=True, db_index=True)  # Indexed
    event_name = models.CharField(max_length=1000, null=True, blank=True, db_index=True)  # Indexed
    event_type = models.CharField(max_length=1000, null=True, blank=True, db_index=True)  # Indexed
    user_identity = models.CharField(max_length=1000, blank=True, null=True)  # Stores username or user info
    region = models.CharField(max_length=1000, blank=True, null=True)  # Indexed
    ip_address = models.GenericIPAddressField(blank=True, null=True, db_index=True)  # Indexed
    user_agent = models.CharField(max_length=3000, blank=True, null=True)  # Indexed
    resources = models.TextField(blank=True, null=True)  # Serialized list of resources as text
    raw_data = models.TextField()  # Serialized JSON as text

    # Use string reference to break circular import
    aws_account = models.ForeignKey('aws.AWSAccount', on_delete=models.CASCADE, related_name='normalized_logs')
    tags = models.ManyToManyField(Tag, related_name='normalized_logs')

    # Utility
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)  # Indexed for sorting by creation time

    def __str__(self):
        return f"{self.event_name} ({self.event_source}) - Case {self.case.name}"


    class Meta:
        indexes = [
            BTreeIndex(fields=["event_source"]),
            BTreeIndex(fields=["event_name"]),
            BTreeIndex(fields=["event_time"]),
            BTreeIndex(fields=["ip_address"]),
            BTreeIndex(fields=["user_agent"]),
            BTreeIndex(fields=["region"]),
        ]
        unique_together = (("case", "event_id"),)




