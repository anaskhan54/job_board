from django.db import models

# Create your models here.
class User(models.Model):
    first_name=models.CharField(max_length=100)
    last_name=models.CharField(max_length=100)
    email=models.EmailField(max_length=100)
    password=models.CharField(max_length=200) #it should be hashed
    salt=models.CharField(max_length=100) #the salt 
    choice=(
        ('job_seeker','Job Seeker'),
        ('company','Company'),
        ('admin','Admin')
    )
    account_type=models.CharField(max_length=100,choices=choice,default='job_seeker')

