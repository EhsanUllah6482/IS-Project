from django.urls import path
from . import views

urlpatterns = [
    path('', views.register, name='register'),
    path('login/', views.login, name='login'),  
    path('logout/', views.logout, name='logout'),
    path('forgotpassword/', views.forgotpassword, name='forgotpassword'),
    path('resetpassword_validate/<uidb64>/<token>/', views.resetpassword_validate, name='resetpassword_validate'),
    path('resetPassword/', views.resetPassword, name='resetPassword'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),  
    path('edit_profile/', views.edit_profile, name='edit_profile'),
    path('change_password/', views.change_password, name='change_password'),
    path('home/',views.predict_insurance,name='home'),
    path('verify-2fa/', views.verify_2fa, name='verify_2fa'),

    path('accounts/login/', views.login, name='login'),  
]
