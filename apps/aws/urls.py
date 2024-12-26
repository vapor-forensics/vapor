from django.urls import path
from django.views.generic import TemplateView

from . import views

app_name = "aws"

urlpatterns = [
    path('<slug:slug>/connect/aws/', views.connect_aws, name='connect_aws'),
    path('accounts/<int:account_id>/edit/', views.edit_account, name='edit_account'),
	path('accounts/<int:account_id>/delete/', views.delete_account, name='delete_account'),
]


