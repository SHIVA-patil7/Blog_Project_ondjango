from django.http import HttpResponse
from django.shortcuts import render,redirect,get_object_or_404
from django.contrib import messages 
from django.contrib.auth.models import User
from .models import *
import random 
from .forms import Userregisterform
from django.core.mail import send_mail 
from django.contrib.auth.hashers import make_password 
from django.contrib.auth import authenticate, login,logout
from django.contrib.auth.forms import AuthenticationForm 
from django.contrib.auth import views as auth_views
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm,PasswordChangeForm
from django.contrib.auth.views import PasswordChangeView
from django.urls import reverse_lazy
from .forms import *

# Create your views here.
def email_list(request):
    emails= User.objects.all()
    return render(request, 'email_list.html', {'emails': emails})



def regform(request):
    if request.method=='POST':
        fm=Userregisterform(request.POST)
        if fm.is_valid():
           
            username=request.POST['username']
            email=request.POST['email']
            password1=request.POST['password1']
            password2=request.POST['password2']
            request.session['username']=username 
            request.session['password1']=password1 
            request.session['email']=email 
           
            #print(request.session['email'])
            if password1==password2:
                if User.objects.filter(username=username).exists():
                    messages.info(request,'User already exists')
                    return redirect('regform')
                elif User.objects.filter(email=email).exists():
                   messages.info(request,'User email ID already exists')
                   return redirect('regform')
                else:
                     
                     fm.save()
                     user_name=authenticate(username=username,password=password1)
                     
                     if user_name is not None:
                        return redirect('email_list')
                
            else:
                messages.info(request,'password mismatch')
                return redirect('regform')
    
    else:
        fm=Userregisterform() 
    return render(request,'register.html',{'form':fm})

    

def email_update(request, pk):
    email= get_object_or_404(User, pk=pk)
    if request.method == "POST":
        form = Userregisterform(request.POST, request.FILES, instance=email)
        if form.is_valid():
            form.save()
            return redirect('verify_email_1')
    else:
        form = Userregisterform(instance=email)
    return render(request, 'email_form.html', {'form': form})

def email_delete(request, pk):
    email = get_object_or_404(User, pk=pk)
    if request.method == "POST":
        email.delete()
        return redirect('email_list')
    return render(request, 'email_confirm_delete.html', {'email': email})





def loginform(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        print(form)
        username=request.POST['username']
        request.session['username']=username
        if form.is_valid():
            print('h1')
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            print(username)
            print(password)
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('send_otp')  # Redirect to a success page
            messages.info(request,'Invalid login')
                
        else:
            messages.info(request,'Form is invalid')
            
    else:
        form = AuthenticationForm()
    return render(request, 'login.html', {'form': form})


def logoutform(request):
    logout(request)
    return redirect('regform')

def send_otp(request):
    user = request.user.email
    otp=''
    for x in range(0,4):
        otp+=str(random.randint(0,9))
    request.session['otp']=otp
    email_subject = 'Your OTP for Login'
    email_body = f'Your OTP for login is {otp}'
    from_email = 'svjoshi885@gmail.com' 
    # recipient_list = [request.session.get('email')]+-
    recipient_list = [user]
    print(recipient_list)

    send_mail(
        email_subject,
        email_body,  
        from_email,
        recipient_list,
        fail_silently=False
    )
    return render(request,'otp.html')


def otp_verification(request):
    if request.method=='POST':
        otp_=request.POST.get('otp')
        if otp_==request.session['otp']:
            messages.info(request,'otp verified successfully')
            return redirect('success')
        else:
            messages.info(request,'otp does not match')
            return render(request,'otp.html')


def send_otp1(request):
    print(f"Email stored in session: {request.session.get('email')}") 

    # request.session["email"] = user
    #print(request.session.get('email'),"in email otp")
    #print(user,"user in otp")
    otp=''
    for x in range(0,4):
        otp+=str(random.randint(0,9))
    request.session['otp']=otp
    print( request.session['otp'])

    email_subject = 'Your OTP for Login'
    email_body = f'Your OTP for login is {otp}'
    from_email = 'svjoshi885@gmail.com' 
    recipient_list = [request.session.get('email')]
    #recipient_list = [user]
    print(recipient_list)

    send_mail(
        email_subject,
        email_body,  
        from_email,
        recipient_list,
        fail_silently=False
    )
    return render(request,'otp1.html')

def otp_verification1(request):
    if request.method=='POST':
        otp_=request.POST.get('otp')
        if otp_==request.session['otp']:
            messages.info(request,'otp verified')
            return redirect('setpassword')
    else:
        messages.info(request,'otp does not match')
        return render(request,'otp1.html')


 

def verify_email(request):
    if request.method == 'POST':
        # Fetch email from POST data
        email=request.POST.get('email')
        request.session['email']=email
        
        print(f"Submitted email: {email}")
        user=User.objects.get(email=email)
        print(user,"user !!!!")
        if user:
            print('otp redirect page')
            messages.info(request, 'Email verified')
            return redirect('send_otp1')  # Redirect to a success page
        else:
            messages.info(request, 'Email does not match')
            return redirect('resetpassword')  # Show the verification page again
    else:
    # If it's not a POST request, redirect to the verification page
        return redirect('resetpassword')
    
def verify_email_1(request):
    if request.method == 'POST':
        # Fetch email from POST data
        email=request.POST.get('email')
        request.session['email']=email
        
        print(f"Submitted email: {email}")
        user=User.objects.get(email=email)
        print(user,"user !!!!")
        if user:
            print('otp redirect page')
            messages.info(request, 'Email verified')
            return redirect('send_otp2')  # Redirect to a success page
        else:
            messages.info(request, 'Email does not match')
            return redirect('email_list')  # Show the verification page again
    else:
    # If it's not a POST request, redirect to the verification page
        return redirect('email_list')
    



def otp_verification2(request):
    if request.method=='POST':
        otp_=request.POST.get('otp')
        if otp_==request.session['otp']:
            messages.info(request,'otp verified')
            return redirect('email_list')
    else:
        messages.info(request,'otp does not match')
        return render(request,'otp2.html')
    


def send_otp2(request):
    print(f"Email stored in session: {request.session.get('email')}") 

    # request.session["email"] = user
    #print(request.session.get('email'),"in email otp")
    #print(user,"user in otp")
    otp=''
    for x in range(0,4):
        otp+=str(random.randint(0,9))
    request.session['otp']=otp
    print( request.session['otp'])

    email_subject = 'Your OTP for Login'
    email_body = f'Your OTP for login is {otp}'
    from_email = 'svjoshi885@gmail.com' 
    recipient_list = [request.session.get('email')]
    #recipient_list = [user]
    print(recipient_list)

    send_mail(
        email_subject,
        email_body,  
        from_email,
        recipient_list,
        fail_silently=False
    )
    return render(request,'otp2.html')


def confirm(request):
    return render(request,'confirm.html') 

def resetpassowrd(request):
    print("in here ")
    print(request.method)
    if request.method=='POST':
        fm = PasswordResetForm(request.POST)
        if fm.is_valid():
                fm.save(
                    request=request,
                    use_https=request.is_secure(),
                    email_template_name='password_reset_email.html'
                )
               
                
                messages.success(request, 'Password reset link sent to your email.')
        else:
            
             return redirect('passwordchange')
            
              
    else:
        print(12344)
        fm=PasswordResetForm()
    return render(request,'password_reset_email.html',{'form':fm})



def setpassowrd(request): 
    if request.method == 'POST':
        print('h1')
        username=request.session.get('username')
        # Ensure the user is logged in (request.user should not be AnonymousUser)
        user=User.objects.get(username=username)
        if user:
            fm = SetPasswordForm(user=request.user, data=request.POST)
            print(request.user)
            
            if fm.is_valid():
                fm.save()
                print('h2')
                return redirect('login')  # Redirect to the login page after password change
            else:
                print('Form is invalid')    
        else:
            print('User is not authenticated')
            return redirect('login')  # Redirect anonymous user to login
    
    else:
        fm = SetPasswordForm(user=request.user) # Redirect anonymous user to login
    
    return render(request, 'setpassword.html', {'form': fm})


class ChangePasswordView(PasswordChangeView):
    form_class = PasswordChangeForm
    success_url = reverse_lazy('login')
    template_name = 'change_password.html'
