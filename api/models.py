from django.db import models

# Create your models here.
class User(models.Model):
    first_name=models.CharField(max_length=100)
    last_name=models.CharField(max_length=100)
    email=models.EmailField(max_length=100,unique=True)
    password=models.CharField(max_length=200) #it should be hashed
    
    choice=(
        ('job_seeker','Job Seeker'),
        ('company','Company'),
        ('admin','Admin')
    )
    account_type=models.CharField(max_length=100,choices=choice,default='job_seeker')
    salt=models.CharField(max_length=100) #the salt 
    
class Job(models.Model):
    company_id=models.ForeignKey(User,on_delete=models.CASCADE)
    job_title=models.CharField(max_length=100)
    job_description=models.TextField()
    location=models.CharField(max_length=100)
    salary=models.IntegerField()
    application_deadline=models.DateField()
    status=models.CharField(max_length=6,choices=(('open','Open'),('closed','Closed')),default='open')
    

class Application(models.Model):
    job_seeker_id=models.ForeignKey(User,on_delete=models.CASCADE)
    job_id=models.ForeignKey(Job,on_delete=models.CASCADE)
    application_date=models.DateField(auto_now_add=True)
    status=models.CharField(max_length=10,choices=(('pending','Pending'),('accepted','Accepted'),('rejected','Rejected')),default='pending')

class PasswordReset(models.Model):
    token=models.CharField(max_length=100)
    isverified=models.BooleanField(default=False)
    user=models.ForeignKey(User,on_delete=models.CASCADE)