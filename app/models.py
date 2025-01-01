from django.db import models
from django.contrib.auth.models import User

# Create your models here.

def upload_path(instance , filename):
    path = '/'.join(['covers',filename])
    return path


class auidioExplaination(models.Model):
    audio = models.FileField(upload_to='audios/') 

class profile (models.Model) : 
    user = models.OneToOneField(User, on_delete=models.CASCADE,blank=True ,  null=True,default='')
    firstname = models.TextField(blank=True ,  null=True)
    lastname = models.TextField(blank=True ,  null=True)
    phone_number = models.TextField(blank=True ,  null=True)
    mail = models.TextField(blank=True ,  null=True)
    dur_start = models.DateField(blank=True ,  null=True) 
    duration = models.IntegerField(blank=True ,  null=True) 
    contacted = models.BooleanField(default=False)
    def __str__(self):
        return " ".join([self.firstname ,self.lastname])


class serie (models.Model) :    
    category = models.IntegerField( null=True , blank=True,default=-1)
    title = models.TextField(blank=True ,  null=True) 
    desc = models.TextField(blank=True ,  null=True) 
    icon =  models.FileField(upload_to='icon/')
    type = models.TextField(blank=True ,  null=True)
    def __str__(self):
        return self.title

class quiz (models.Model) : 
    serie = models.ForeignKey(serie,on_delete=models.CASCADE , null=True , blank=True)
    audio_content =  models.FileField(upload_to='audios/' ,null= True , blank=True)
    auidio_explaination =  models.FileField(upload_to='audios/',null= True , blank=True)
    picture =   models.FileField(upload_to='img/',null= True , blank=True)
    correctAnswer =   models.FileField(upload_to='img/',null= True , blank=True)


class question (models.Model) : 
    quiz = models.ForeignKey(quiz , on_delete=models.CASCADE , null= True , blank=True)
    content = models.TextField(blank=True ,  null=True) 
    explication = models.TextField(blank=True ,  null=True)
    def __str__(self):
        return self.content
    

class answer (models.Model) :
    question = models.ForeignKey(question , on_delete=models.CASCADE , blank=True , null=True) 
    content = models.TextField() 
    status = models.IntegerField(blank=True , null=True , default=0)
    def __str__(self):
        return self.content


class recievingMails (models.Model) : 
    fullNames =  models.TextField() 
    gmail =  models.TextField() 
    subject =  models.TextField()
    message =  models.TextField()
    seen = models.BooleanField(default=False)
    def __str__(self):
        return self.fullNames