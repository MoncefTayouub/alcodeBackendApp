from django.urls import path 
from . import views 
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.views import TokenVerifyView


urlpatterns = [
    path('', views.Category_queries ) ,
    path('owner/user', views.userView ) ,
    path('owner/serie', views.serieCroud ) ,
    path('owner/quiz', views.quizCroud ) ,
    path('owner/answer', views.answerCroud ) ,
    path('search', views.search ) ,
    path('userlogin', views.user_login ) ,
    path('owner/profiles/<str:category>', views.ownerProfiles ) ,
    path('loadData', views.loadData ) ,
    path('userResaults', views.seeRes ) ,
    # path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('verify_token', views.verify_user_login),
    path('contactUs', views.contactUs),

]