from django.db import models

# Create your models here.
class User(models.Model):
    email = models.EmailField(unique=True)
    
class Profile(models.Model):
    nickname = models.CharField(max_length=20, unique=True)
    prfile_pic = models.ImageField()
    name = models.CharField(max_length=10)
    birthday = models.DateField()
    phonenumber = models.IntegerField()
    
    