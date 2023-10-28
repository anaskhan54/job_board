from django.shortcuts import render,redirect
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.parsers import JSONParser
from rest_framework import status
from api.serializers import UserSerializer,JobSerializer,ApplicationSerializer
from api.forms import SignUpForm,LoginForm,JobPostForm
import hashlib,bcrypt
from django.http import QueryDict
from api.models import User,Job,PasswordReset,Application
import jwt
from django.conf import settings
from django.core.mail import send_mail
import secrets
import urllib.parse
import urllib.request
import json
from datetime import datetime


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
        if request.POST['account_type']=='admin':
            return Response({"message":"You can not create admin account"})
        salt=str(bcrypt.gensalt())
        data={}
        for key,value in request.POST.items():
            data[key]=value
        data['password']+=salt
        data['salt']=salt
        data['password']=hashlib.sha256(data['password'].encode('utf-8')).hexdigest()
        final_data=QueryDict('',mutable=True)
        for key,value in data.items():
            final_data.update({key: value})
        recaptcha_response=request.POST.get('g-recaptcha-response')
        print(recaptcha_response)
        url = 'https://www.google.com/recaptcha/api/siteverify'
        values = {
                'secret': settings.GOOGLE_RECAPTCHA_SECRET_KEY,
                'response': recaptcha_response
            }
        data = urllib.parse.urlencode(values).encode('utf-8')
        req = urllib.request.Request(url, data)
        response = urllib.request.urlopen(req)
        result = json.load(response)
        if result['success'] or True:#remove true after testing!!!!!!!!!!!!!!!!!!!
            form=SignUpForm(final_data)
            if form.is_valid():
                form.save()
                return Response({"message":"success"})
            else:
                return Response(form.errors)
        else:
            return Response({"message":"Invalid Captcha"})
        
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
        jwt_token=request.COOKIES.get('jwt_token').encode('utf-8')
        secret=settings.JWT_SECRET
        my_data=jwt.decode(jwt_token,secret,algorithms=["HS256"])
        user_id=my_data.get('user')
        user=User.objects.get(id=user_id)
        data=JSONParser().parse(request)
        data['company_id']=user.id
        if data['application_deadline']<str(datetime.now().date()):
            return Response({"message":"deadline can not be in past"})
        if data['salary'] < 0:
            return Response({"message":"salary cannot be negative"})
        if data['salary']<3000:
            return Response({"message":"salary cannot be less than 3000"})
        serializer=JobSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"success"})
        else:
            return Response(serializer.errors)

class JobUpdateView(APIView):
    def get(self,request,id):
        job=Job.objects.get(id=id)
        form=JobPostForm(instance=job)
        return render(request,'api/jobpost.html',context={'form':form})
    def put(self,request,id):
        jwt_token=request.COOKIES.get('jwt_token').encode('utf-8')
        secret=settings.JWT_SECRET
        my_data=jwt.decode(jwt_token,secret,algorithms=["HS256"])
        user_id=my_data.get('user')
        try:
            company_id=Job.objects.filter(id=id).values('company_id')[0]['company_id']
        except:
            return Response({"message":"job does not exist"})
        if user_id!=company_id:
            return Response({"message":"you can not update this job"})
        
        user=User.objects.get(id=user_id)
        data=JSONParser().parse(request)
        data['company_id']=user.id
        job_to_update=Job.objects.get(id=id)
        serializer=JobSerializer(job_to_update,data=data,partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"success"})
        else:
            return Response(serializer.errors)
        
class PasswordResetView(APIView):
    def get(self,request):
        return render(request,'api/passwordreset.html')
    def post(self,request):
        token=secrets.token_urlsafe(11)
        email=request.POST['email']
        
        try:
            user=User.objects.get(email=email)
        except:
            return Response({"message":"password reset link is sent to the email if exists"}) 
        password_reset=PasswordReset(token=token,user=user)
        password_reset.save()
        subject="Request For Password Reset"
        message=f"Your Password Reset link is: http://127.0.0.1:8000/password/reset/{token}"
        sender="professor00333@gmail.com"
        receiver=[email]
        send_mail(subject,message,sender,receiver)
        return Response({"message":"password reset link is sent to the email if exists"})
        
class PasswordResetActivateView(APIView):
    def get(self,request,token):
        try:    
            password_reset=PasswordReset.objects.get(token=token)
        except:

            return Response({"message":"The token is expired or is invalid"})
        password_reset.isverified=True
        password_reset.save()
        return render(request,'api/verifytoken.html')
    def post(self,request,token):
        new_password=str(request.POST['password'])
        
        try:
            password_resets=PasswordReset.objects.get(token=token)
        except:
            return Response({"message":"The token is expired or is invalid"})
        email=password_resets.user.email
        user=User.objects.get(email=email)
        salt=str(bcrypt.gensalt())
        user.password=hashing(new_password,salt,email)
        user.salt=salt
        user.save()
        password_resets.delete()
        if PasswordReset.objects.filter(user=user).exists():
            PasswordReset.objects.filter(user=user).delete()
        if request.COOKIES.get('jwt_token'):
            response=Response({"message":"password changed successfully"})
            response.delete_cookie('jwt_token')
            return response
        return Response({"message":"password changed successfully"})

class LogoutView(APIView):
    def get(self,request):
        if request.COOKIES.get('jwt_token'):

            response=Response({"message":"success"})
            response.delete_cookie('jwt_token')
            return response
        else:
            return Response({"message":"you are not logged in, please login first"})
class JobApplyView(APIView):
    def get(self,request):
        return render(request,'api/jobapply.html')
    def post(self,request):
        jwt_token=request.COOKIES.get('jwt_token').encode('utf-8')
        secret=settings.JWT_SECRET
        my_data=jwt.decode(jwt_token,secret,algorithms=["HS256"])
        user_id=my_data.get('user')
        user=User.objects.get(id=user_id)
        data=JSONParser().parse(request)
        data['job_seeker_id']=user.id
        job_id=data['job_id']
        serializer=ApplicationSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
           
            subject="Application Submitted"
            description=Job.objects.filter(id=job_id).values('job_description')
            message=f"Your application has been submitted successfully\n\nJob Description:\n{description[0]['job_description']}"
            sender="professor00333@gmail.com"
            receiver=[user.email]
            
            send_mail(subject,message,sender,receiver)
            #send mail to company
            subject="New Application"
            message=f"New Applicant for the job id {job_id}\n\n Applicants Details:\nName:{user.first_name} {user.last_name}\nEmail:{user.email}\n\n"
            sender="professor00333@gmail.com"
            receiver=[Job.objects.filter(id=job_id).values('company_id__email')[0]['company_id__email']]
            send_mail(subject,message,sender,receiver)

            return Response({"message":"success"})
        else:
            return Response(serializer.errors)
        
    
class ApplicationListView(APIView):
    def get(self,request):
        jwt_token=request.COOKIES.get('jwt_token').encode('utf-8')
        secret=settings.JWT_SECRET
        my_data=jwt.decode(jwt_token,secret,algorithms=["HS256"])
        user_id=my_data.get('user')
        user=User.objects.get(id=user_id)
        
        applications=Application.objects.filter(job_seeker_id=user.id)
        serializer=ApplicationSerializer(applications,many=True)
        return Response(serializer.data)
    
class ApplicationCancelView(APIView):
    def delete(self, request, id):
        jwt_token=request.COOKIES.get('jwt_token').encode('utf-8')
        secret=settings.JWT_SECRET
        my_data=jwt.decode(jwt_token,secret,algorithms=["HS256"])
        user_id=my_data.get('user')
        user=User.objects.get(id=user_id)
        try:
            application=Application.objects.filter(id=1)
        except:
            return Response({"message":"application does not exist"})
        if(application.values()[0]['job_seeker_id_id']==user.id):
            application.delete()
            return Response({"message":"success"})
        else:
            return Response({"message":"you can not delete this application"})
        
class AdminDeleteView(APIView):
    def delete(self, request, email):
        user_email = email

        # Check if the user exists
        if User.objects.filter(email=user_email).exists():
            user = User.objects.get(email=user_email)
        else:
            return Response({"message": "User does not exist"})

        jwt_token = request.COOKIES.get('jwt_token')
        secret = settings.JWT_SECRET

        if jwt_token:
            jwt_token = jwt_token.encode('utf-8')
            my_data = jwt.decode(jwt_token, secret, algorithms=["HS256"])
            user_id = my_data.get('user')
            user_authenticated = User.objects.get(id=user_id)

            if user_authenticated.account_type != "admin":
                return Response({"message": "You are not an admin"})
        else:
            return Response({"message": "Login First"})

        user.delete()
        return Response({"message": "User deleted successfully"})

    
class ApplicationAllView(APIView):
    def get(self,request):
        applications=Application.objects.all()
        serializer=ApplicationSerializer(applications,many=True)
        return Response(serializer.data)
    
    
        
        


    

        
    




