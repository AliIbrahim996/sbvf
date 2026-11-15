"""URL routes for the Django sample (read statically by sbvf.sast.routes)."""
from django.urls import path

from . import views

urlpatterns = [
    path("profile/<int:uid>/", views.profile),
    path("go/", views.go),
    path("safe/", views.safe),
]
