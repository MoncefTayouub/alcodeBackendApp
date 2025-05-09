from django.urls import path 
from . import views 
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.views import TokenVerifyView


urlpatterns = [
    path('', views.Category_queries ) ,
    path('owner/user', views.userView ) ,
    path('owner/serie', views.serieCroud ) ,
    path('owner/quiz', views.quizCroud ) ,
    path('owner/clearImgExp', views.clearExpImg ) ,
    path('owner/answer', views.answerCroud ) ,
    path('search', views.search ) ,
    path('userlogin', views.user_login ) ,
    path('owner/profiles/<str:category>', views.ownerProfiles ) ,
    path('course/content/<str:category>', views.filterCategory ) ,
    path('loadData/<int:value>', views.loadData ) ,
    path('userResaults', views.seeRes ) ,
    # path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('verify_token', views.verify_user_login),
    path('logout', views.logout),
    path('userlogin/check', views.checkStuff),
    path('userlogin/duration', views.checkDuration),
    path('contactUs', views.contactUs),

]