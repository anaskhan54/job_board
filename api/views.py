from django.shortcuts import render,redirect
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from api.serializers import UserSerializer,JobSerializer
from api.forms import SignUpForm,LoginForm,JobPostForm
import hashlib,bcrypt
from django.http import QueryDict
from api.models import User,Job

class SignUpView(APIView):
    def get(self,request):
        form=SignUpForm()
        return render(request, 'api/signup.html',context={'form':form})
    def post(self,request):
        salt=str(bcrypt.gensalt())
        data={}
        for key,value in request.POST.items():
            data[key]=value
        data['password']+=salt
        data['salt']=salt
        print(data)
        data['password']=hashlib.sha256(data['password'].encode('utf-8')).hexdigest()
        final_data=QueryDict('',mutable=True)
        for key,value in data.items():
            final_data.update({key: value})
        
        print(final_data)
        form=SignUpForm(final_data)
        if form.is_valid():
            form.save()
            return Response({"message":"success"})
        
class LoginView(APIView):
    def get(self,request):
        form=LoginForm()
        return render(request,'api/login.html',context={'form':form})
    
    def post(self,request):
        try:
            email=request.POST['email']
        except:
            return Response({"message":"user does not exist"})
        
        password=request.POST['password']
        salt=User.objects.get(email=email).salt
        pw=(password+salt).encode('utf-8')
        pw=hashlib.sha256(pw).hexdigest()
        hash=User.objects.get(email=email).password
        print(pw)
        print(hash)
        if(hash==pw):
            return Response({"message":"login successful"})
        else:
            return Response({"message":"incorrect credentials"})
        
        
    
class JobListView(APIView):
    def get(self,request):
        jobs=Job.objects.all()
        serializer=JobSerializer(jobs,many=True)
        return Response(serializer.data)
class JobPostView(APIView):
    def get(self,request):
        form=JobPostForm()
        return render(request,'api/jobpost.html',context={'form':form})
    def post(self,request):
        pass
    




