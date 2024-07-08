from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.RegisterViewSet.as_view({'post': 'create'}), name='register'),
    path('login/', views.LoginViewSet.as_view({'post': 'create'}), name='login'),
    path('users/<int:pk>/', views.UserViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy','patch' : 'p_update'}), name='users'),
    # path('all_users/',views.User_getall_Objects.as_view())
]