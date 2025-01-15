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
    path('accounts/<int:account_id>/pull-log-source/', views.pull_log_source, name='pull_log_source'),
    path('accounts/<int:account_id>/account-details/', views.account_details, name='account_details'),
    path('logsource/<slug:slug>//details/', views.aws_logsource_details, name='aws_logsource_details'),
    path('logs/fetch/account/<int:account_id>/', views.trigger_log_fetch, name='trigger_log_fetch'),
    path('fetch-management-events/<int:account_id>/', views.trigger_management_event_fetch, name='fetch_management_events'),

]

