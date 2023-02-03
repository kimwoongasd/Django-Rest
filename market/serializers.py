from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import User, Post, Profile


User = get_user_model()

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = [
            'realname',
            'username',
            'prfile_pic',
            'provie',
        ]

class UserSerializer(serializers.ModelSerializer):
    profile = ProfileSerializer(read_only=True)
    class Meta:
        model = User
        fields = [
            'nickname',
            'email',
            'profile',
        ]

class RegisterSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=150, write_only=True)
    last_name = serializers.CharField(max_length=150, write_only=True)
    email = serializers.EmailField(write_only=True)
    nickname = serializers.CharField(max_length=150, write_only=True)
    password = serializers.CharField(write_only=True)
        
    def create(self, validated_data):
        user = User.objects.create_user(  # type: ignore
            validated_data
        )
        
        return user

class PostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Post
        fields = '__all__'

