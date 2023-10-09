from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.messages import constants
from django.urls import reverse
from django.contrib.auth import authenticate, login as auth_login
from django.http import HttpResponse

def cadastro(request):
    if request.method == 'GET':
        return render(request, 'cadastro.html')
    elif request.method == 'POST':
        primeiro_nome = request.POST.get('primeiro_nome')
        ultimo_nome = request.POST.get('ultimo_nome')
        email = request.POST.get('email')
        senha = request.POST.get('senha')
        username = request.POST.get('username')
        confirmar_senha = request.POST.get('confirmar_senha')

        verify_user = User.objects.filter(username=username)
        if verify_user:
            messages.add_message(request, constants.ERROR, 'Usuário já registrado')
            return redirect(reverse('cadastro'))
        
        if len(senha) <= 7:
            messages.add_message(request, constants.ERROR, 'A senha deve ter mais de 7 caracteres')
            return redirect(reverse('cadastro'))
            
        if senha == confirmar_senha:
            try:
                user = User(
                    first_name=primeiro_nome,
                    last_name=ultimo_nome, 
                    username=username,
                    email=email,
                    password=senha,
                )
                user.save()
                messages.add_message(request, constants.SUCCESS, 'Usuário registrado com sucesso')
                return redirect(reverse('login'))
            except:
                messages.add_message(request, constants.ERROR, 'Não foi possível registrar o usuário')
        else:
            messages.add_message(request, constants.ERROR, 'As senhas não coicidem')

        return redirect(reverse('cadastro'))

def login(request):
    if request.method == 'GET':
        return render(request, 'login.html')

    elif request.method == 'POST':
        username = request.POST.get('username')
        senha = request.POST.get('senha')
        user = authenticate(username=username, password=senha)

        if user:
            auth_login(request, user)
            return HttpResponse('sucesso')
        else:
            messages.add_message(request, constants.ERROR, 'Não foi possível realizar o login')
            return redirect(reverse('login'))