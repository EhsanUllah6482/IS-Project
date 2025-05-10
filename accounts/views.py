from django.shortcuts import render,redirect,get_object_or_404
from .forms import *
from .models import Account
from django.contrib import messages,auth
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse

from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage
import requests
# Create your views here.


import random

def generate_otp():
    return str(random.randint(100000, 999999))


def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            phone_number = form.cleaned_data['phone_number']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            username = email.split("@")[0]
            user = Account.objects.create_user(first_name=first_name, last_name=last_name, email=email, username=username, password=password)
            user.phone_number = phone_number
            user.save()
            messages.success(request,'Registration Successful')


            # Create a user profile
            profile = UserProfile()
            profile.user_id = user.id
            profile.profile_picture = 'photos/default/default-user.jpg'
            profile.save()

            # USER ACTIVATION
            current_site = get_current_site(request)
            mail_subject = 'Please activate your account'
            message = render_to_string('accounts/account_verification_email.html', {
                'user': user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()
            return redirect('/accounts/login/?command=verification&email='+email)
    else:
        form = RegistrationForm()
    context = {
        'form': form,
    }
    return render(request, 'accounts/register.html', context)
@login_required
def home(request):
    return render(request,'home.html')

from datetime import datetime

def login(request):
    if request.method == "POST":
        email = request.POST['email']
        password = request.POST['password']

        user = auth.authenticate(email=email, password=password)
        if user is not None:
            otp = generate_otp()
            request.session['pre_auth_user_id'] = user.id
            request.session['otp'] = otp
            request.session['otp_created_at'] = datetime.now().isoformat()  # store timestamp

            # Send OTP via email
            mail_subject = 'Your Login Verification Code'
            message = f"Your OTP for login is: {otp}"
            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()

            return redirect('verify_2fa')
        else:
            messages.error(request, 'Invalid Credentials')
            return redirect('login')
    return render(request, 'accounts/login.html')

from datetime import datetime, timedelta

def verify_2fa(request):
    if request.method == 'POST':
        entered_otp = request.POST['otp']
        session_otp = request.session.get('otp')
        otp_created_at = request.session.get('otp_created_at')
        user_id = request.session.get('pre_auth_user_id')

        if not session_otp or not otp_created_at or not user_id:
            messages.error(request, 'Session expired. Please try again.')
            return redirect('login')

        # Validate OTP expiry (5 minutes)
        otp_time = datetime.fromisoformat(otp_created_at)
        if datetime.now() - otp_time > timedelta(minutes=5):
            messages.error(request, 'Verification code expired. Please log in again.')
            return redirect('login')

        if entered_otp == session_otp:
            user = Account.objects.get(id=user_id)
            auth.login(request, user)
            for key in ['otp', 'pre_auth_user_id', 'otp_created_at']:
                if key in request.session:
                    del request.session[key]
            return redirect('home')
        else:
            messages.error(request, 'Invalid verification code')
            return redirect('verify_2fa')
    return render(request, 'accounts/verify_2fa.html')

# def login(request):
#     if request.method == "POST":
#         email = request.POST['email']
#         password = request.POST['password']

#         user = auth.authenticate(email=email, password=password)
#         if user is not None:
#             otp = generate_otp()
#             request.session['pre_auth_user_id'] = user.id
#             request.session['otp'] = otp

#             # Send OTP via email
#             mail_subject = 'Your Login Verification Code'
#             message = f"Your OTP for login is: {otp}"
#             to_email = email
#             send_email = EmailMessage(mail_subject, message, to=[to_email])
#             send_email.send()

#             return redirect('verify_2fa')
#         else:
#             messages.error(request, 'Invalid Credentials')
#             return redirect('login')
#     return render(request, 'accounts/login.html')

# def verify_2fa(request):
#     if request.method == 'POST':
#         entered_otp = request.POST['otp']
#         session_otp = request.session.get('otp')
#         user_id = request.session.get('pre_auth_user_id')

#         if entered_otp == session_otp:
#             user = Account.objects.get(id=user_id)
#             auth.login(request, user)
#             del request.session['otp']
#             del request.session['pre_auth_user_id']
#             return redirect('home')
#         else:
#             messages.error(request, 'Invalid verification code')
#             return redirect('verify_2fa')
#     return render(request, 'accounts/verify_2fa.html')


@login_required
def logout(request):
    auth.logout(request)
    messages.success(request,'You are logged Out.')
    return redirect('login')



def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Congratulations! Your account is activated.')
        return redirect('login')
    else:
        messages.error(request, 'Invalid activation link')
        return redirect('register')





def forgotpassword(request):
    if request.method == 'POST':
        email = request.POST['email']
        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email__exact=email)

            current_site = get_current_site(request)
            mail_subject = 'Reset Your Password'
            message = render_to_string('accounts/reset_password_email.html', {
                'user': user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()

            messages.success(request, 'Password reset email has been sent to your email address.')
            return redirect('login')
        else:
            messages.error(request, 'Account does not exist!')
            return redirect('forgotPassword')
    return render(request, 'accounts/forgotPassword.html')


def resetpassword_validate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        request.session['uid'] = uid
        messages.success(request, 'Please reset your password')
        return redirect('resetPassword')
    else:
        messages.error(request, 'This link has been expired!')
        return redirect('login')


def resetPassword(request):
    if request.method == 'POST':
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if password == confirm_password:
            uid = request.session.get('uid')
            user = Account.objects.get(pk=uid)
            user.set_password(password)
            user.save()
            messages.success(request, 'Password reset successful')
            return redirect('login')
        else:
            messages.error(request, 'Password do not match!')
            return redirect('resetPassword')
    else:
        return render(request, 'accounts/resetPassword.html')

@login_required(login_url='login')
def edit_profile(request):
    userprofile = get_object_or_404(UserProfile, user=request.user)
    if request.method == 'POST':
        user_form = UserForm(request.POST, instance=request.user)
        profile_form = UserProfileForm(request.POST, request.FILES, instance=userprofile)
        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            messages.success(request, 'Your profile has been updated.')
            return redirect('edit_profile')
    else:
        user_form = UserForm(instance=request.user)
        profile_form = UserProfileForm(instance=userprofile)
    context = {
        'user_form': user_form,
        'profile_form': profile_form,
        'userprofile': userprofile,
    }
    return render(request, 'accounts/edit_profile.html', context)



@login_required(login_url='login')
def change_password(request):
    if request.method == 'POST':
        current_password = request.POST['current_password']
        new_password = request.POST['new_password']
        confirm_password = request.POST['confirm_password']

        user = Account.objects.get(username__exact=request.user.username)

        if new_password == confirm_password:
            success = user.check_password(current_password)
            if success:
                user.set_password(new_password)
                user.save()
                # auth.logout(request)
                messages.success(request, 'Password updated successfully.')
                return redirect('change_password')
            else:
                messages.error(request, 'Please enter valid current password')
                return redirect('change_password')
        else:
            messages.error(request, 'Password does not match!')
            return redirect('change_password')
    return render(request, 'accounts/change_password.html')

import pandas as pd
import pickle
from django.shortcuts import render
from django.conf import settings
import os
model_path = os.path.join(settings.BASE_DIR, 'accounts', 'ml_models', 'insurancemodelf.pkl')
model = pickle.load(open(model_path, 'rb'))

@login_required
def predict_insurance(request):
    if request.method == 'POST':
        age = int(request.POST['age'])
        sex = request.POST['sex']
        bmi = float(request.POST['bmi'])
        children = int(request.POST['children'])
        smoker = request.POST['smoker']
        region = request.POST['region']

        data = pd.DataFrame({
            'age': [age],
            'sex': [sex],
            'bmi': [bmi],
            'children': [children],
            'smoker': [smoker],
            'region': [region]
        })

        data['smoker'] = data['smoker'].map({'yes': 1, 'no': 0})
        data = data.drop(['sex', 'region'], axis=1)

        prediction = model.predict(data)[0]
        return render(request, 'home.html', {'prediction': prediction})

    return render(request, 'home.html')


