"""URL routes for the IDOR sample (read statically by sbvf.sast.routes)."""
from django.urls import path

from . import views

urlpatterns = [
    path("orders/<int:order_id>/", views.get_order),
    path("my-orders/<int:order_id>/", views.my_order),
]
