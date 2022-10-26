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
    
class Post(models.Model):
    title = models.CharField(max_length=10)
    context = models.TextField(max_length=1000)
    price = models.IntegerField()
    post_pic = models.ImageField(null=True)
    dt_created = models.DateField(auto_now_add=True)
    dt_update = models.DateField(auto_now=True)
    