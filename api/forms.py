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
        fields="__all__"