from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .serializers import UserSerializers, LoginSerializers
from django.contrib.auth.models import User
from rest_framework import viewsets
from rest_framework.authentication import BasicAuthentication
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
    

# auth token
# password fetch

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializers

    def get(self, request, pk, format=None):
        user = self.get_object(pk)
        user = UserSerializers(user)
        return Response(user.data)

    def put(self, request, pk, format=None):
        user = self.get_object(pk)
        serializer = UserSerializers(user, data=request.data)
        
        if serializer.is_valid():
            # Hash the password before saving
            password = serializer.validated_data.get('password')
            hashed_password = make_password(password)
            print("0-------->>", password, hashed_password)
            serializer.validated_data['password'] = hashed_password
            
            # Save the serializer with hashed password
            serializer.save()
            
            return Response(serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, pk):
        user = self.get_object(pk)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    def p_update(self, request, pk, format=None):
        user = self.queryset.get(pk=pk)
        serializer = UserSerializers(user, data=request.data, partial=True)
        if serializer.is_valid():
            # Update only specific fields
            serializer.save(username=request.data.get('username'), email=request.data.get('email'))
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginViewSet(viewsets.ViewSet):
    serializer_class = LoginSerializers
    authentication_classes = [BasicAuthentication]
    permission_classes = [IsAuthenticated]

    
    def get(self, request, format=None): 
        content = { 
            
            # `django.contrib.auth.User` instance 
            'user': str(request.user), 
            
            # None 
            'auth': str(request.auth), 
        } 
        return Response(content)

    def create(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        # Perform login logic here, e.g., generating tokens
        return Response(serializer.data, status=status.HTTP_200_OK)

class RegisterViewSet(viewsets.ViewSet):
    serializer_class = UserSerializers
    authentication_classes = [BasicAuthentication]  # Specify BasicAuthentication as a list
    permission_classes = [IsAuthenticated]

    def create(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()  # Save the user object
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)