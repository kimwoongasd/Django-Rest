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
    nickname = models.CharField(max_length=20)
    is_superuser = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    objects = UserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    auth = models.CharField(max_length=128, null=True, blank=True)
    realname = models.CharField(max_length=64, null=True, blank=True)
    nickname = models.CharField(max_length=64, unique=True, null=True, blank=True)
    prfile_pic = models.ImageField(null=True, blank=True)
    provider = models.CharField(max_length=64, default='basic')
    
    def __str__(self):
        return self.user.nickname
    
    def create_profile(self, user, data):
        last_name = data.get("last_name", '')
        first_name = data.get("first_name", '')
        profile = Profile(
            user=user,
            realname = last_name + first_name,
        )
        
        profile.save()
        
        return 
    
class Post(models.Model):
    title = models.CharField(max_length=10)
    context = models.TextField(max_length=1000)
    price = models.IntegerField()
    post_pic = models.ImageField(null=True)
    dt_created = models.DateField(auto_now_add=True)
    dt_update = models.DateField(auto_now=True)
    
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user")
    