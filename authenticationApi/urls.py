from django.contrib import admin
from django.urls import path,include
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from django.views.generic import TemplateView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/user/', include('account.urls')),


    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

     path('swagger-ui/', TemplateView.as_view(
        template_name='docs/swagger-ui.html',
        extra_context={'schema_url':'openapi-schema'}
    ), name='swagger-ui'),

    path('redoc/', TemplateView.as_view(
        template_name='docs/redoc.html',
        extra_context={'schema_url':'openapi-schema'}
    ), name='redoc'),
]
