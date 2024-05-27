import json, re, traceback

# from django.shortcuts import render
from django.http import JsonResponse
from django.views import View
from django.core.exceptions import ValidationError
from django.db.models import Q
from .models import Account
from django.contrib.sessions.models import Session
from datetime import datetime
from django.conf import settings
from django.utils.crypto import get_random_string
from django.contrib.sessions.backends.db import SessionStore
import json
import bcrypt

MINIMUM_PASSWORD_LENGTH = 8

class SignUpView(View):
    def post(self,request):
        data = json.loads(request.body)

        try:
            username = data.get('username', None)
            email = data.get('email', None)
            userID = data.get('userID', None)
            password = data.get('password', None)
            
            if not(username and email and userID and password):
                return JsonResponse({'message' : 'KEY_ERROR'}, status=400)
            
            validate_email(email)
            validate_password(password)
            
            user = Account.objects.filter(Q(username=username) | Q(email=email))
            if not user:
                Account.objects.create(
                    username=username,
                    email=email,
                    userID=userID,
                    password=bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                )
                return JsonResponse({'message':'SUCCESS'}, status=200)
            
            return JsonResponse({'message':'USER_ALREADY_EXISTS'}, status=409)
        except KeyError:
            return JsonResponse({'message':'KEY_ERROR'}, status=400)
            

def validate_email(email):
    pattern = re.compile('^.+@+.+\.+.+$')
    if not pattern.match(email):
        return JsonResponse({'message' : 'INVALID_EMAIL'}, status=400)
    
def validate_password(password):
    if len(password)<MINIMUM_PASSWORD_LENGTH:
        return JsonResponse({'message':'SHORT_PASSWORD'}, status=400)

class LogInView(View):
    def post(self, request):
        data = json.loads(request.body)

        try:
            userID = data.get('userID', None)
            password = data.get('password', None)

            if not (userID and password):
                return JsonResponse({'message': 'KEY_ERROR'}, status=400)

            try:
                user = Account.objects.get(userID=userID)

                if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
                    # Create a new session
                    session = SessionStore()
                    session['user_userID'] = user.userID
                    session.create()

                    # Set session cookie
                    response = JsonResponse({'message': 'SUCCESS'}, status=200)
                    response.set_cookie(settings.SESSION_COOKIE_NAME, session.session_key, httponly=True, max_age=settings.SESSION_COOKIE_AGE)
                    return response
                else:
                    return JsonResponse({'message': 'INVALID_CREDENTIALS'}, status=401)
            except Account.DoesNotExist:
                return JsonResponse({'message': 'INVALID_CREDENTIALS'}, status=401)

        except KeyError:
            return JsonResponse({'message': 'KEY_ERROR'}, status=400)
            
class LogOutView(View):
    def post(self,request):
        try:
            session_key = request.COOKIES.get(settings.SESSION_COOKIE_NAME)
            if session_key:
                try:
                    session=Session.objects.get(session_key=session_key)
                    session.delete()
                    
                    response = JsonResponse({'message': 'SUCCESS'}, status=200)
                    response.delete_cookie(settings.SESSION_COOKIE_NAME)
                    return response
                except Session.DoesNotExist:
                    return JsonResponse({'message': 'SESSION_NOT_FOUND'}, status=404)
            else:
                return JsonResponse({'message': 'NO_SESSION_COOKIE'}, status=400)
        except KeyError:
            return JsonResponse({'message': 'KEY_ERROR'}, status=400)
    
    