from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework.exceptions import AuthenticationFailed

class UserSerializers(serializers.ModelSerializer):
    password=serializers.CharField(write_only=True)

    class Meta:
        model=User
        fields=['username','email','password']

    def create(self, validated_data):
        user=User.objects.create_user(**validated_data)
        return user
    

class LoginSerializers(serializers.ModelSerializer):
    username=serializers.CharField()
    password=serializers.CharField(write_only=True)

    class Meta:
        model=User
        fields=['username','password']

    def validate(self, data):
        username=data.get('username','')
        password=data.get('password','')
        if username and password:
            user=User.objects.filter(username=username).first()
            if user is None:
                raise AuthenticationFailed('User not found')
            if not user.check_password(password):
                raise AuthenticationFailed('Incorrect password')
        else:
            raise AuthenticationFailed('Username and password required')
        
        return user