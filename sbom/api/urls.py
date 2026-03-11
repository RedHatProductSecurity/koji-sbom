"""API URL configuration."""
from django.urls import path

from . import views

urlpatterns = [
    path("status", views.status),
    path("streams", views.streams),
    path("sbom/<str:stream>", views.sbom),
]
