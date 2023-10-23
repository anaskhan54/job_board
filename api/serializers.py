from rest_framework import serializers
from api.models import *

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields="__all__"

class JobSerializer(serializers.ModelSerializer):
    class Meta:
        model=Job
        fields="__all__"