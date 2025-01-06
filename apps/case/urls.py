from django.urls import path
from django.views.generic import TemplateView

from . import views

app_name = "case"

urlpatterns = [
    path('new/', views.create_case, name='create_case'),
    path('<slug:slug>/', views.case_detail, name='case_detail'),
    path('<slug:slug>/edit/', views.edit_case, name='edit_case'),
    path('<slug:slug>/connect/', views.connect_client, name='connect_client'),
    path('<slug:slug>/connected-accounts/', views.list_connected_accounts, name='list_connected_accounts'),
]

