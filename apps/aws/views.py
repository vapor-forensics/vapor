import boto3
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import AWSAccount, AWSResource
from .forms import AWSAccountForm
from apps.case.models import Case
import boto3
from .utils import validate_aws_credentials 
from django.contrib import messages
from .tasks import pull_aws_resources_task, pull_log_source_task



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

# List all the resources for the AWS account
@login_required
def list_aws_resources(request, account_id):
    aws_account = get_object_or_404(AWSAccount, id=account_id)

    # Group resources by their type
    resources = AWSResource.objects.filter(account=aws_account).order_by('resource_type', 'resource_name')
    grouped_resources = {}
    for resource in resources:
        grouped_resources.setdefault(resource.resource_type, []).append(resource)

    context = {
        'aws_account': aws_account,
        'grouped_resources': grouped_resources,
    }
    return render(request, 'aws/list_aws_resources.html', context)

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