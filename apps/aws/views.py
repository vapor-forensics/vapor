import boto3
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import AWSAccount, AWSResource, AWSLogSource
from .forms import AWSAccountForm
from apps.case.models import Case
import boto3
from .utils import validate_aws_credentials 
from django.contrib import messages
from .tasks import pull_aws_resources_task, pull_log_source_task
from datetime import datetime
from django.http import JsonResponse
from django.utils.timezone import make_aware
from .tasks import fetch_and_normalize_logs_task, fetch_management_history_task

import logging

logger = logging.getLogger(__name__)


# This is used to add access to the aws account to be investigated and connect it to vapor.
@login_required
def connect_aws(request, slug):
    case = get_object_or_404(Case, slug=slug)

    if request.method == "POST":
        form = AWSAccountForm(request.POST)
        if form.is_valid():
            aws_account = form.save(commit=False)
            aws_account.case = case
            aws_account.added_by = request.user

            # Validate credentials
            is_valid, error_message = validate_aws_credentials(
                aws_access_key=aws_account.aws_access_key,
                aws_secret_key=aws_account.aws_secret_key,
                region=aws_account.aws_region
            )
            aws_account.validated = is_valid
            aws_account.save()

            # Provide user feedback
            if is_valid:
                messages.success(request, "AWS account connected successfully!")
            else:
                messages.error(request, f"AWS account saved, but validation failed: {error_message}")

            # Redirect to connected accounts page
            return redirect('case:list_connected_accounts', slug=case.slug)
    else:
        form = AWSAccountForm()

    return render(request, 'aws/connect_aws.html', {'form': form, 'case': case})

# Edit aws connection
@login_required
def edit_account(request, account_id):
    account = get_object_or_404(AWSAccount, id=account_id)
    if request.method == "POST":
        form = AWSAccountForm(request.POST, instance=account)
        if form.is_valid():
            form.save()
            return redirect('case:list_connected_accounts', slug=account.case.slug)
    else:
        form = AWSAccountForm(instance=account)

    return render(request, 'aws/edit_account.html', {'form': form, 'account': account})

# Delete aws account
@login_required
def delete_account(request, account_id):
    account = get_object_or_404(AWSAccount, id=account_id)
    slug = account.case.slug  # Save the slug for redirection
    account.delete()
    return redirect('case:list_connected_accounts', slug=slug)


#This is the trigger for getting the resources of the AWS account.
#It calls a background worker to get the data (need to add progress bar)
@login_required
def pull_resources_view(request, account_id):
    aws_account = get_object_or_404(AWSAccount, id=account_id)

    if not aws_account.validated:
        messages.error(request, "Cannot pull resources because the AWS account credentials are not validated.")
        return redirect('case:list_connected_accounts', slug=aws_account.case.slug)

    # Trigger background task
    pull_aws_resources_task.delay(account_id)
    messages.info(request, "Resource pulling has started. This may take a few minutes.")

    return redirect('case:list_connected_accounts', slug=aws_account.case.slug)

# Open a modal to show the details of the resources
@login_required
def aws_resource_details(request, resource_id):
    """
    Fetch and return details for a specific AWS resource.
    """
    resource = get_object_or_404(AWSResource, id=resource_id)
    return render(request, 'aws/resource_details.html', {'resource': resource})

#This is the trigger for getting the available logs of the AWS account.
#It calls a background worker to get the data (need to add progress bar)
@login_required
def pull_log_source(request, account_id):
    aws_account = get_object_or_404(AWSAccount, id=account_id)

    if not aws_account.validated:
        messages.error(request, "Cannot pull log sources because the AWS account credentials are not validated.")
        return redirect('case:list_connected_accounts', slug=aws_account.case.slug)

    # Trigger background task
    pull_log_source_task.delay(account_id)
    messages.info(request, "Discovering available log sources. This may take a few minutes.")

    return redirect('case:list_connected_accounts', slug=aws_account.case.slug)

# this renders both the aws resources and logging sources into one page
@login_required
def account_details(request, account_id):
    aws_account = get_object_or_404(AWSAccount, id=account_id)

    # Group resources by their type
    resources = AWSResource.objects.filter(account=aws_account).order_by('resource_type', 'resource_name')
    grouped_resources = {}
    for resource in resources:
        grouped_resources.setdefault(resource.resource_type, []).append(resource)

    # Group log sources by service
    log_sources = AWSLogSource.objects.filter(account=aws_account).order_by('service_name', 'log_name')
    grouped_log_sources = {}
    for log_source in log_sources:
        grouped_log_sources.setdefault(log_source.service_name, []).append(log_source)

    # Add error messages if applicable
    error_messages = []
    if not resources.exists():
        error_messages.append("No AWS resources found for this account.")
    if not log_sources.exists():
        error_messages.append("No AWS log sources found for this account.")

    context = {
        'aws_account': aws_account,
        'grouped_resources': grouped_resources,
        'grouped_log_sources': grouped_log_sources,
        'error_messages': error_messages,
    }
    return render(request, 'aws/account_details.html', context)

@login_required
def aws_logsource_details(request, slug):
    """
    Fetch and return details for a specific AWS log source using its slug.
    """
    log_source = get_object_or_404(AWSLogSource, slug=slug)

    context = {
        'log_source': log_source,
    }

    return render(request, 'aws/logsource_details.html', context)


@login_required
def trigger_log_fetch(request, account_id):
    aws_account = get_object_or_404(AWSAccount, account_id=account_id)

    if request.method == 'POST':
        # Parse datetime from form submission
        start_time = make_aware(datetime.strptime(request.POST.get('start_time'), '%Y-%m-%dT%H:%M'))
        end_time = make_aware(datetime.strptime(request.POST.get('end_time'), '%Y-%m-%dT%H:%M'))

        # Get selected resources or all resources for the account
        resource_ids = request.POST.getlist('resource_ids', None)
        if not resource_ids:
            resources = AWSResource.objects.filter(account=aws_account)
            resource_ids = list(resources.values_list('id', flat=True))

        # Trigger background task
        fetch_and_normalize_logs_task.delay(account_id, aws_account.case.id, start_time, end_time, resource_ids)

        # Add success message
        messages.success(request, "Logs are being gathered. You will be notified once the process is complete.")

        # Redirect to the list of connected accounts
        return redirect('case:list_connected_accounts', slug=aws_account.case.slug)

    # Render the form for GET requests
    resources = AWSResource.objects.filter(account=aws_account)
    return render(request, 'aws/trigger_log_fetch.html', {'aws_account': aws_account, 'resources': resources})

@login_required
def trigger_management_event_fetch(request, account_id):
    aws_account = get_object_or_404(AWSAccount, account_id=account_id)
    logger.info(f"Triggering fetch for AWS account {account_id}")

    # Trigger background task
    fetch_management_history_task.delay(account_id, aws_account.case.id)
    messages.success(request, "Management event history is being fetched.")
    logger.info(f"Task queued for AWS account {account_id}")

    return redirect('case:list_connected_accounts', slug=aws_account.case.slug)

