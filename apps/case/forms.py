from django import forms
from .models import Case

# Create a new case for the investigation
class CaseForm(forms.ModelForm):
    class Meta:
        model = Case
        fields = ['name', 'description', 'status']
        widgets = {
            'status': forms.Select(attrs={'class': 'select select-bordered'}),
            'description': forms.Textarea(attrs={'class': 'textarea textarea-bordered'}),
        }
