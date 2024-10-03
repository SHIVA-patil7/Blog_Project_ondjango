from django.urls import path
from Signup_page import views
from django.views.generic import TemplateView 
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('sign_up/',views.regform,name='regform'),
    path('login/',views.loginform,name='login'),
    path('send_otp',views.send_otp,name='send_otp'),
    path('otp_verification/',views.otp_verification,name='otp_verification'),
    path('success/',TemplateView.as_view(template_name='seccess.html'),name="success"),
    path('forgetpassword/',TemplateView.as_view(template_name='forgotpassword.html'),name='verifypassword'),
    path('verifyemail/',views.verify_email,name='verify_email'),
    path('verifyemail1/',views.verify_email_1,name='verify_email_1'),
    path('send_otp2',views.send_otp2,name='send_otp2'),
    path('otp_verification2/',views.otp_verification2,name='otp_verification2'),

    path('confirmemail/',views.confirm,name='conform'),
    path('otp_verification1/',views.otp_verification1,name='otp_verification1'),
    path('passwordchange/',TemplateView.as_view(template_name='password_reset_email.html'),name='passwordchange'),
    path('resetpassword/',views.resetpassowrd,name='resetpassword'),
    path('send_otp1',views.send_otp1,name='send_otp1'),
    path('set_password/',views.setpassowrd,name='setpassword'),
    path('logout/',views.logoutform,name='logout'),
    path('changepassword',views.ChangePasswordView.as_view(),name='changepassword'),
    path('email_lists/',views.email_list,name="email_list"),
    path('email/<int:pk>/update/', views.email_update, name='email_update'),
    path('email/<int:pk>/delete/', views.email_delete, name='email_delete'),
]