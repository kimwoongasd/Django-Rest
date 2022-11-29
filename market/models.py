from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin

# Create your models here.
class UserManager(BaseUserManager):
    def create_user(self, email, password, nickname, **kwargs):
        if not email:
            raise ValueError("이메일을 입력해 주세요")
        
        user = self.model(
            email = email,
            nickname = nickname,
        )
        
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email=None, password=None, nickname="슈퍼", **extra_fields):
        superuser = self.create_user(
            email = email,
            password = password,
            nickname = nickname,
        )
        superuser.is_staff = True
        superuser.is_superuser = True
        superuser.is_active = True
        
        superuser.save(using=self._db)
        return superuser
    
class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    nickname = models.CharField(max_length=20, unique=True)
    is_superuser = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    objects = UserManager()
    
    USERNAME_FIELD = 'email'
    
    
class Profile(models.Model):
    prfile_pic = models.ImageField()
    
class Post(models.Model):
    title = models.CharField(max_length=10)
    context = models.TextField(max_length=1000)
    price = models.IntegerField()
    post_pic = models.ImageField(null=True)
    dt_created = models.DateField(auto_now_add=True)
    dt_update = models.DateField(auto_now=True)
    