from django import forms
from api.models import User
from django.forms import ModelForm

class SignUpForm(ModelForm):
    class Meta:
        model=User
        fields="__all__"
        