from django.db import models
from django.conf import settings
from apps.case.models import Case
from django.utils.text import slugify
from apps.data.models import Tag

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

    # Tags
    tags = models.ManyToManyField(Tag, related_name='aws_resource')

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

    # Tags
    tags = models.ManyToManyField(Tag, related_name='aws_log_source')

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

# Model to store credentials pulled from credential report api
class AWSCredential(models.Model):
    account = models.ForeignKey(AWSAccount, on_delete=models.CASCADE, related_name='credentials')
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='aws_credentials')
    user = models.CharField(max_length=300)
    user_arn = models.CharField(max_length=300)
    user_creation_time = models.DateTimeField(null=True, blank=True)
    password_enabled = models.BooleanField(default=False)
    password_last_used = models.DateTimeField(null=True, blank=True)
    password_last_changed = models.DateTimeField(null=True, blank=True)
    password_next_rotation_date = models.DateTimeField(null=True, blank=True)
    mfa_active = models.BooleanField(default=False)
    access_key_1_active = models.BooleanField(default=False)
    access_key_1_last_rotated = models.DateTimeField(null=True, blank=True)
    access_key_1_last_used_date = models.DateTimeField(null=True, blank=True)
    access_key_1_last_used_region = models.CharField(max_length=300, null=True, blank=True)
    access_key_1_last_used_service = models.CharField(max_length=300, null=True, blank=True)
    access_key_2_active = models.BooleanField(default=False)
    access_key_2_last_rotated = models.DateTimeField(null=True, blank=True)
    access_key_2_last_used_date = models.DateTimeField(null=True, blank=True)
    access_key_2_last_used_region = models.CharField(max_length=300, null=True, blank=True)
    access_key_2_last_used_service = models.CharField(max_length=300, null=True, blank=True)
    cert_1_active = models.BooleanField(default=False)
    cert_1_last_rotated = models.DateTimeField(null=True, blank=True)
    cert_2_active = models.BooleanField(default=False)
    cert_2_last_rotated = models.DateTimeField(null=True, blank=True)
    slug = models.SlugField(max_length=255, unique=True, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    # Tags
    tags = models.ManyToManyField(Tag, related_name='aws_credential')

    class Meta:
        unique_together = ('account', 'user')

    def save(self, *args, **kwargs):
        if not self.slug:
            base_slug = slugify(f"{self.user}-{self.user_arn}")
            unique_slug = base_slug
            num = 1
            while AWSCredential.objects.filter(slug=unique_slug).exists():
                unique_slug = f"{base_slug}-{num}"
                num += 1
            self.slug = unique_slug
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.user} - {self.user_arn} for Account {self.account.account_id}"
    
    
    

