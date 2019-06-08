from django.shortcuts import render, redirect
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required

from django.http import HttpResponse
from django.conf import settings

from social_django.models import UserSocialAuth

import base64
import hashlib
import hmac
import json


@login_required
def home(request):
    return render(request, 'index.html')


def login_user(request):
    return render(request, 'login.html')


@login_required
def logout_user(request):
    logout(request)
    return redirect('login')


def deauth(request):
    try:
        signed_request = request.POST['signed_request']
        encoded_sig, payload = signed_request.split('.')
    except (ValueError, KeyError):
        return HttpResponse(status=400, content='Invalid request')

    try:
        decoded_payload = base64.urlsafe_b64decode(payload + "==").decode('utf-8')
        decoded_payload = json.loads(decoded_payload)

        if ((type(decoded_payload) is not dict)
                or 'user_id' not in decoded_payload.keys()):
            return HttpResponse(status=400, content='Invalid payload data')

    except (ValueError, json.JSONDecodeError):
        return HttpResponse(status=400, content='Could not decode payload')

    try:
        secret = settings.SOCIAL_AUTH_FACEBOOK_SECRET

        sig = base64.urlsafe_b64decode(encoded_sig + "==")
        expected_sig = hmac.new(bytes(secret, 'utf-8'),
                                bytes(payload, 'utf-8'), hashlib.sha256)
    except ValueError:
        return HttpResponse(status=400, content='Could not decode signature')

    if not hmac.compare_digest(expected_sig.digest(), sig):
        return HttpResponse(status=400, content='Invalid request')

    fb_uid = decoded_payload['user_id']

    # Here I suppose, that fb_uid is a string for facebook uid
    user = UserSocialAuth.objects.get(uid=fb_uid).user
    user.is_active = False
    user.save()

    return HttpResponse(status=200)
