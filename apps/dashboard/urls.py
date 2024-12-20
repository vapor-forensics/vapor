from django.urls import path

from . import views

app_name = "dashboard"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("api/user-signups/", views.UserSignupStatsView.as_view(), name="user_signups_api"),
]
