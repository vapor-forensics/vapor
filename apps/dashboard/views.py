from datetime import datetime, timedelta

from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import user_passes_test
from django.template.response import TemplateResponse
from django.utils import timezone
from drf_spectacular.utils import extend_schema
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.dashboard.forms import DateRangeForm
from apps.dashboard.serializers import UserSignupStatsSerializer
from apps.dashboard.services import get_user_signups
from apps.users.models import CustomUser


def _string_to_date(date_str: str) -> datetime.date:
    date_format = "%Y-%m-%d"
    return datetime.strptime(date_str, date_format).date()


@user_passes_test(lambda u: u.is_superuser, login_url="/404")
@staff_member_required
def dashboard(request):
    end_str = request.GET.get("end")
    if end_str:
        end = _string_to_date(end_str)
    else:
        end = timezone.now().date() + timedelta(days=1)
    start_str = request.GET.get("start")
    if start_str:
        start = _string_to_date(start_str)
    else:
        start = end - timedelta(days=90)
    serializer = UserSignupStatsSerializer(get_user_signups(start, end), many=True)
    form = DateRangeForm(initial={"start": start, "end": end})
    start_value = CustomUser.objects.filter(date_joined__lt=start).count()
    return TemplateResponse(
        request,
        "dashboard/user_dashboard.html",
        context={
            "active_tab": "project-dashboard",
            "signup_data": serializer.data,
            "form": form,
            "start": start.isoformat(),
            "end": end.isoformat(),
            "start_value": start_value,
        },
    )


class UserSignupStatsView(APIView):
    permission_classes = [IsAdminUser]

    @extend_schema(request=None, responses=UserSignupStatsSerializer(many=True))
    def get(self, request):
        serializer = UserSignupStatsSerializer(get_user_signups(), many=True)
        return Response(serializer.data)
