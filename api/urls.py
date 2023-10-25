from django.urls import path
from . import views
from rest_framework_simplejwt.views import(
                    TokenObtainPairView,
                    TokenRefreshView,
)
urlpatterns = [
    path('',views.LandingPageView.as_view(),name='landing-page'),
    path('signup/',views.SignUpView.as_view(),name='signup'),
    path('login/',views.LoginView.as_view(),name='login'),
    path('password/reset/',views.PasswordResetView.as_view(),name='password-reset'),
    path('password/reset/<str:token>/',views.PasswordResetActivateView.as_view(),name='password-reset-activate'),
    path('job/list/',views.JobListView.as_view(),name='job-list'),
    path('job/post/',views.JobPostView.as_view(),name='job-post'), #accessible to companies
    path('job/apply/',views.JobApplyView.as_view(),name='job-apply')
    
    


    
]