from django.urls import path
from . import views

urlpatterns = [
    path('',views.LandingPageView.as_view(),name='landing-page'),
    path('signup/',views.SignUpView.as_view(),name='signup'),
    path('login/',views.LoginView.as_view(),name='login'),
    path('password/reset/',views.PasswordResetView.as_view(),name='password-reset'),
    path('logout/',views.LogoutView.as_view(),name='logout'),
    path('password/reset/<str:token>/',views.PasswordResetActivateView.as_view(),name='password-reset-activate'),
    path('job/list/',views.JobListView.as_view(),name='job-list'),
    path('job/post/',views.JobPostView.as_view(),name='job-post'), #accessible to companies
    path('job/update/<int:id>',views.JobUpdateView.as_view(),name='job-update'),
    path('job/apply/',views.JobApplyView.as_view(),name='job-apply'),
    path('application/list/',views.ApplicationListView.as_view(),name='application-list'),#accessible to job_seeker
    path('application/all/',views.ApplicationAllView.as_view(),name='application-all'),#accessible to admin
    path('application/cancel/<int:id>',views.ApplicationCancelView.as_view(),name='application-cancel'),#accessible accessible to job seekers

    path('delete/user/<str:email>',views.AdminDeleteView.as_view(),name='admin-delete') #accessible to admin


    
]