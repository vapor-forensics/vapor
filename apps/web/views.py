from django.shortcuts import render
from django.utils.translation import gettext_lazy as _

from django.contrib.auth.decorators import login_required
from apps.case.models import Case

def home(request):
    if request.user.is_authenticated:
        cases = request.user.cases.all()
        return render(
            request,
            "web/app_home.html",
            context={
                "active_tab": "dashboard",
                "page_title": _("Dashboard"),
                "cases": cases,
            },
        )
    else:
        return render(request, "web/landing_page.html")


def simulate_error(request):
    raise Exception("This is a simulated error.")

