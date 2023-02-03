from django.db import models, transaction
from django.contrib.auth.models import AbstractUser, PermissionsMixin
from django.contrib.auth.base_user import BaseUserManager
# Create your models here.
class UserManager(BaseUserManager):
    @transaction.atomic
    def create_user(self, validate_data):
        nickname = validate_data["nickname"]
        email = validate_data["email"]
        password = validate_data["password"]
        first_name = validate_data['first_name']
        last_name = validate_data['last_name']
        
        if not nickname:
            raise ValueError('아이디는 필수 항목입니다.')
        if not email:
            raise ValueError('이메일은 필수 항목입니다.')
        if not password:
            raise ValueError('패드워드는 필수 항목입니다.')
        
        
        user = self.model(
            nickname=nickname,
            first_name=first_name,
            last_name=last_name,
            email = self.normalize_email(email)
        )
        user.set_password(password)
        user.save(using=self._db)
        profile = Profile.create_profile(self, user=user, data=validate_data)  # type: ignore
        profile.save()
        
        return user
    
    def create_superuser(self, email=None, password=None, nickname="슈퍼", **extra_fields):
        superuser = self.model(
            email = self.normalize_email(email),
            password = password,
            nickname = nickname,
        )
        superuser.set_password(password)
        superuser.is_staff = True
        superuser.is_superuser = True
        superuser.is_active = True
        
        superuser.save(using=self._db)
        profile = Profile.create_profile(self, user=superuser, data={})  # type: ignore
        profile.save()
        return superuser
    
class User(AbstractUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    nickname = models.CharField(max_length=20)
    is_superuser = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    object = UserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    @property
    def name(self):
        if not self.last_name:
            return self.first_name

        return f'{self.first_name} {self.last_name}'
    
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    realname = models.CharField(max_length=128, null=True, blank=True)
    username = models.CharField(max_length=128, null=True, blank=True)
    prfile_pic = models.ImageField(null=True, blank=True)
    provier = models.CharField(max_length=128, null=True, blank=True)
    
    def __str__(self):
        return self.user.nickname
    
    def create_profile(self, user, data):
        first_name = data.get("first_name", "")
        last_name = data.get("last_name", "")
        
        profile = Profile(
            user=user,
            realname = first_name + last_name,
        )
        profile.save()
        return profile
    
class Post(models.Model):
    title = models.CharField(max_length=10)
    context = models.TextField(max_length=1000)
    price = models.IntegerField()
    post_pic = models.ImageField(null=True)
    dt_created = models.DateField(auto_now_add=True)
    dt_update = models.DateField(auto_now=True)
    
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user")
    