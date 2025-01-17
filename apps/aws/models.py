from django.db import models
from django.conf import settings
from apps.case.models import Case
from django.utils.text import slugify

# Used to show and access the AWS account for the case
class AWSAccount(models.Model):
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='aws_accounts')
    account_id = models.CharField(max_length=50, unique=True)
    aws_access_key = models.CharField(max_length=100)
    aws_secret_key = models.CharField(max_length=100)
    aws_region = models.CharField(max_length=50, default="us-east-1")
    added_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='added_aws_accounts')
    added_at = models.DateTimeField(auto_now_add=True)
    validated = models.BooleanField(default=False)

    def __str__(self):
        return f"AWS Account {self.account_id} for Case {self.case.name}"

# Get an overview of all the resources in the account for annalysis
class AWSResource(models.Model):
    account = models.ForeignKey('AWSAccount', on_delete=models.CASCADE, related_name='resources')
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='aws_resources')
    resource_id = models.CharField(max_length=200)
    resource_type = models.CharField(max_length=100)
    resource_name = models.CharField(max_length=200, blank=True, null=True)
    resource_details = models.JSONField(blank=True, null=True)
    aws_region = models.CharField(max_length=50, blank=True, null=True)
    slug = models.SlugField(max_length=255, unique=True, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.slug:
            base_slug = slugify(f"{self.resource_type}-{self.resource_id}")
            unique_slug = base_slug
            num = 1
            while AWSResource.objects.filter(slug=unique_slug).exists():
                unique_slug = f"{base_slug}-{num}"
                num += 1
            self.slug = unique_slug
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.resource_type} - {self.resource_name or self.resource_id} for Account {self.account.account_id}"


class AWSLogSource(models.Model):
    account = models.ForeignKey('AWSAccount', on_delete=models.CASCADE, related_name='log_sources')
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='aws_log_sources')
    service_name = models.CharField(max_length=100)
    log_name = models.CharField(max_length=255)
    log_details = models.JSONField(blank=True, null=True)
    status = models.CharField(max_length=50)
    aws_region = models.CharField(max_length=50, blank=True, null=True)
    slug = models.SlugField(max_length=255, unique=True, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.slug:
            base_slug = slugify(f"{self.service_name}-{self.log_name}")
            unique_slug = base_slug
            num = 1
            while AWSResource.objects.filter(slug=unique_slug).exists():
                unique_slug = f"{base_slug}-{num}"
                num += 1
            self.slug = unique_slug
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.service_name} - {self.log_name or self.status} for Account {self.account.account_id}"
