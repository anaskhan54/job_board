from django.shortcuts import render,redirect
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from api.serializers import UserSerializer,JobSerializer
from api.forms import SignUpForm,LoginForm,JobPostForm
import hashlib,bcrypt
from django.http import QueryDict
from api.models import User,Job,PasswordReset
import jwt
from django.conf import settings
from django.core.mail import send_mail
import secrets


def hashing(password,salt,email):
    password+=salt
    return hashlib.sha256(password.encode('utf-8')).hexdigest()
class LandingPageView(APIView):
    def get(self,request):
        return render(request,'api/landing.html')
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
            user=User.objects.get(email=email)
        except:
            return Response({"message":"user does not exist"})
        
        password=request.POST['password']
        salt=user.salt
        pw=(password+salt).encode('utf-8')
        pw=hashlib.sha256(pw).hexdigest()
        hash=user.password
        data={"account_type":user.account_type,
              "user":user.id}
        if(hash==pw):
            #login successful
            secret=settings.JWT_SECRET
            token=jwt.encode(data,secret,algorithm="HS256")
            response=Response({"jwt_token":token})
            response.set_cookie(key='jwt_token',value=token)
            return response
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
        form=JobPostForm(request.POST)
        if form.is_valid():
            form.save()
            return Response({"message":"success"})
        else:
            
            return Response(form.errors)
        
class PasswordResetView(APIView):
    def get(self,request):
        return render(request,'api/passwordreset.html')
    def post(self,request):
        token=secrets.token_urlsafe(11)
        email=request.POST['email']
        x=0
        try:
            user=User.objects.get(email=email)
        except:
            x=1 #do nothing
        password_reset=PasswordReset(token=token,user=user)
        password_reset.save()
        subject="Request For Password Reset"
        message=f"Your Password Reset link is: http://127.0.0.1:8000/password/reset/{token}"
        sender="professor00333@gmail.com"
        receiver=[email]
        if x==1:#dont send email
            pass
        else:
            send_mail(subject,message,sender,receiver)
        return Response({"message":"password reset link is sent to the email if exists"})
        
class PasswordResetActivateView(APIView):
    def get(self,request,token):
        try:    
            password_reset=PasswordReset.objects.get(token=token)
        except:

            return Response({"message":"Invalid token."})
        password_reset.isverified=True
        password_reset.save()
        return render(request,'api/verifytoken.html')
    def post(self,request,token):
        new_password=str(request.POST['password'])
        print(new_password)
        try:
            password_resets=PasswordReset.objects.get(token=token)
        except:
            return Response({"message":"Invalid token. "})
        email=password_resets.user.email
        user=User.objects.get(email=email)
        salt=str(bcrypt.gensalt())
        user.password=hashing(new_password,salt,email)
        user.salt=salt
        user.save()
        return Response({"message":"password changed successfully"})
    
class JobApplyView(APIView):
    def get(self,request):
        return render(request,'api/jobapply.html')
    def post(self,request,id):

        id=request.POST['id']
        secret=settings.JWT_SECRETbject
        job_applied_for=Job.objects.get(id=objectid)
        token=request.COOKIES.get('jwr_token')
        secret=settings.JWT_SECRET
        data=jwt.decode(token,secret,algorithms=["HS256"])
        userid=data.get("user")

    

        
    




