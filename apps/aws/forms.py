from django import forms
from .models import AWSAccount, AWSResource

class AWSAccountForm(forms.ModelForm):
    class Meta:
        model = AWSAccount
        fields = ['account_id', 'aws_access_key', 'aws_secret_key', 'aws_region']
        widgets = {
            'aws_secret_key': forms.PasswordInput(),
        }

class FetchCloudTrailLogsForm(forms.Form):
    resource = forms.ModelChoiceField(
        label="S3 Bucket",
        queryset=AWSResource.objects.filter(resource_type="S3"),
        widget=forms.Select(attrs={"class": "form-select", "id": "id_resource"})
    )
    prefix = forms.CharField(
        label="Selected Prefix",
        required=False,
        help_text="Click through subfolders to select a prefix where CloudTrail logs are stored.",
        widget=forms.TextInput(attrs={"class": "form-control", "readonly": True, "id": "id_prefix"})
    )
    start_date = forms.DateField(
        label="Start Date",
        widget=forms.DateInput(attrs={"type": "date", "class": "form-control"})
    )
    end_date = forms.DateField(
        label="End Date",
        widget=forms.DateInput(attrs={"type": "date", "class": "form-control"})
    )