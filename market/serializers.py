from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import User

User = get_user_model()
class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'
        
    def create(self, validated_data):
        nickname = validated_data.get('nickname')
        email = validated_data.get('email')
        password = validated_data.get('password')
        user = User(
            nickname = nickname,
            email = email,
        )
        
        user.set_password(password)
        user.save()
        return user
    
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'