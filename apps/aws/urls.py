from django.urls import path
from django.views.generic import TemplateView

from . import views

app_name = "aws"

urlpatterns = [
    path('<slug:slug>/connect/aws/', views.connect_aws, name='connect_aws'),
    path('accounts/<int:account_id>/edit/', views.edit_account, name='edit_account'),
	path('accounts/<int:account_id>/delete/', views.delete_account, name='delete_account'),
    path('accounts/<int:account_id>/pull-resources/', views.pull_resources_view, name='pull_aws_resources'),
    path('resources/<int:resource_id>/details/', views.aws_resource_details, name='aws_resource_details'),
    path('accounts/<int:account_id>/account-resources/', views.account_resources, name='account_resources'),
    path('logsource/<slug:slug>//details/', views.aws_logsource_details, name='aws_logsource_details'),
    path('fetch-management-events/<int:account_id>/', views.trigger_management_event_fetch, name='fetch_management_events'),
    path('browse-s3-structure/', views.browse_s3_structure, name='browse_s3_structure'),
    path('fetch-logs/<int:account_id>/', views.fetch_cloudtrail_logs, name='fetch_cloudtrail_logs'),
    path('accounts/<int:account_id>/logs/', views.normalized_logs_view, name='normalized_logs'),
    path('credential/<slug:slug>/', views.aws_credential_details, name='aws_credential_details'),
]

