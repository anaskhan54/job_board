from django import forms
from api.models import User,Job
from django.forms import ModelForm

class SignUpForm(ModelForm):
    class Meta:
        model=User
        fields="__all__"

class LoginForm(ModelForm):
    class Meta:
        model=User
        fields="__all__"        

class JobPostForm(ModelForm):
    class Meta:
        model=Job
        fields=["company_id","job_title","job_description",
                "location",
                "salary",
                "application_deadline"]