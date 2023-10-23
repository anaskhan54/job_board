from django.urls import path
from . import views
from rest_framework_simplejwt.views import(
                    TokenObtainPairView,
                    TokenRefreshView,
)
urlpatterns = [
    path('token/',TokenObtainPairView.as_view(),name='token_obtain_pair'),
    path('token/refresh/',TokenRefreshView.as_view(),name='token_refresh'),
    path('signup/',views.SignUpView.as_view(),name='signup'),
    path('login/',views.LoginView.as_view(),name='login'),
    path('job/list/',views.JobListView.as_view(),name='job-list'),
    
]