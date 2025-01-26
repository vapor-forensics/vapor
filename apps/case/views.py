from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Case
from .forms import CaseForm
from apps.aws.models import AWSAccount

# Create a new case for the investigation (this is the first step)
@login_required
def create_case(request):
    if request.method == "POST":
        form = CaseForm(request.POST)
        if form.is_valid():
            case = form.save(commit=False)
            case.created_by = request.user
            case.save()
            case.users.add(request.user)  # Add the creator to the case's users
            return redirect("case:case_detail", slug=case.slug)  # Redirect to the case detail view
    else:
        form = CaseForm()

    return render(request, "case/create_case.html", {"form": form})

# This is used to view the details of a case
@login_required
def case_detail(request, slug):
    case = get_object_or_404(Case, slug=slug)

    # AWS accounts linked to the case
    aws_accounts = AWSAccount.objects.filter(case=case)

    # Add GCP and Azure placeholders
    gcp_placeholder = True
    azure_placeholder = True

    return render(request, "case/case_detail.html", {
        "case": case,
        "aws_accounts": aws_accounts,
        "gcp_placeholder": gcp_placeholder,
        "azure_placeholder": azure_placeholder,
    })

# this is used to edit the details of a case
@login_required
def edit_case(request, slug):
    case = get_object_or_404(Case, slug=slug)

    # Ensure only the creator or an authorized user can edit
    if request.user != case.created_by:
        return redirect('case_detail', slug=slug)

    if request.method == "POST":
        form = CaseForm(request.POST, instance=case)
        if form.is_valid():
            form.save()
            return redirect('case:case_detail', slug=case.slug)
    else:
        form = CaseForm(instance=case)

    return render(request, 'case/edit_case.html', {'form': form, 'case': case})

# This will start the workflow to connect to a clients account and get data
@login_required
def connect_client(request, slug):
    case = get_object_or_404(Case, slug=slug)
    return render(request, 'case/connect_client.html', {'case': case})
