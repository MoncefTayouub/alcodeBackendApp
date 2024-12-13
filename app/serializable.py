from dataclasses import fields
from rest_framework import serializers
from .models import *



class serieSER(serializers.ModelSerializer):
    class Meta :
        fields = '__all__'
        model = serie   


class quizSER(serializers.ModelSerializer):
    class Meta :
        fields = '__all__'
        model = quiz   

class answerSER(serializers.ModelSerializer):
    class Meta :
        fields = '__all__'
        model = answer 

class recievingMailsSER(serializers.ModelSerializer):
    class Meta :
        fields = '__all__'
        model = recievingMails 

class answerSERsec(serializers.ModelSerializer):
    class Meta :
        model = answer   
        exclude = ['status']

class questionSER(serializers.ModelSerializer):
    class Meta :
        fields = '__all__'
        model = question   

class profileSER(serializers.ModelSerializer):
    class Meta :
        fields = '__all__'
        model = profile   
