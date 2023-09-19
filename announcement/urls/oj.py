from django.urls import path

from ..views.oj import AnnouncementAPI

urlpatterns = [
    path("announcement/", AnnouncementAPI.as_view(), name="announcement_api"),
]
