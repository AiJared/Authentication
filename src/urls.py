from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include

from rest_framework.documentation import include_docs_urls

API_TITLE = "Portal"
API_DESCRIPTION = "Student Portal"


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include_docs_urls(title=API_TITLE,
                                description=API_DESCRIPTION
                                )),
    path("api/v1/", include("api.urls")),
]
