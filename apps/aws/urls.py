from django.urls import path
from django.views.generic import TemplateView

from . import views

app_name = "aws"

urlpatterns = [
    path('<slug:slug>/connect/aws/', views.connect_aws, name='connect_aws'),
    path('accounts/<int:account_id>/edit/', views.edit_account, name='edit_account'),
	path('accounts/<int:account_id>/delete/', views.delete_account, name='delete_account'),
    path('accounts/<int:account_id>/pull-resources/', views.pull_resources_view, name='pull_aws_resources'),
    path('accounts/<int:account_id>/resources/', views.list_aws_resources, name='list_aws_resources'),
    path('resources/<int:resource_id>/details/', views.aws_resource_details, name='aws_resource_details'),

]


