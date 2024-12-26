from django import forms
from .models import AWSAccount

class AWSAccountForm(forms.ModelForm):
    class Meta:
        model = AWSAccount
        fields = ['account_id', 'aws_access_key', 'aws_secret_key', 'aws_region']
        widgets = {
            'aws_secret_key': forms.PasswordInput(),
        }
