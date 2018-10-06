# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from time import strftime
from .models import User


# Create your views here.
def index(request):
    if 'user_id' not in request.session:
        # request.session['user_id'] = False
        return redirect('users:new')

    if 'logged_in' not in request.session:
        # request.session['logged_in'] = False
        return redirect('users:new')

    # find the user id of the logged in user
    user_id = int(request.session['user_id'])
    print "*" * 80
    print "Here is the USER ID from session:", user_id
    user_list = User.objects.all()
    specific_user = User.objects.get(id=user_id)
    print "*" * 80
    print "Here is the specific user from db:", specific_user

    context = {
        'users': user_list,
        'specific_user_id': specific_user.id,
        'first_name': specific_user.first_name,
        'last_name': specific_user.last_name,
    }
    return render(request, 'users/index.html', context)

def new(request):
    if 'logged_in' not in request.session:
        request.session['logged_in'] = False

    context = {}
    return render(request, 'users/add.html', context)

def create(request):
    if request.method == 'POST':

        valid, result = User.objects.validate_and_create_user(request.POST)
        print "*" * 80
        print "Successfully entered the create route."
        
        if valid:
            request.session['user_id'] = result
            print "*" * 80
            print "Here is the result info:", result
            return redirect('users:index')
        else:
            for error in result:
                messages.error(request, error)
            return redirect('users:new')
    else:
        return redirect('users:new')

def show(request, user_id):
    context = {
        "user" : User.objects.get(id=user_id),
    }

    return render(request, 'users/show.html', context)

def edit(request, user_id):
    if 'user_id' not in request.session:
        return redirect('users:new')

    try:
        user = User.objects.get(id=user_id)
    except:
        return redirect('users:index')

    context = {
        'user': user,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'email': user.email,
        # "permission_level": user.permission_level
    }
    return render(request, 'users/edit.html', context)

def login(request):
    if request.method == "POST":

        valid, result = User.objects.login_user(request.POST)
        if not valid:
            for error in result:
                messages.error(request, error)
            return redirect('users:new')
        else:
            request.session['user_id'] = result
            request.session['logged_in'] = result
            # print "=" * 80
            # print "login route user_id is: ", result
            return redirect('users:index')
    else:
        return redirect('users:new')

def delete(request, user_id):
    if request.method == 'POST':
        User.objects.delete_user_by_id(user_id)
    return redirect('users:index')

def logout(request):
    request.session.clear()
    return redirect('users:index')

