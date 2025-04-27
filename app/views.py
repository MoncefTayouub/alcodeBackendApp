from django.shortcuts import render
from django.http import JsonResponse
from unicodedata import category
from django.shortcuts import render
from django.shortcuts import render
from .models import * 
from rest_framework.response import *
from rest_framework.decorators import api_view , parser_classes
from rest_framework import permissions
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.renderers import * 
from django.core.files.images import ImageFile
from django.core.mail import *
from django.conf import settings
from django.contrib.auth import authenticate , login
import random
import string
from django.contrib.auth.models import User
from calendar import *
from .Manipulation import *
import json
from .serializable import * 
# Create your views here.
from datetime import * 
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Q
from rest_framework_simplejwt.tokens import RefreshToken
import jwt 
from django.http import FileResponse
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.http import JsonResponse


@api_view(['GET','POST','PUT','DELETE'])
def Category_queries(request):    
    return Response('you are home')


@api_view(['GET','POST','PUT','DELETE'])
def filterCategory(request,category):  
    if request.method == 'GET' :    
        rq = serie.objects.filter(category=category)
        data = rq.order_by('-id')[:18]
        return Response({
            'content' : serieSER(data,many=True).data    
        })
        
    return Response ()

@api_view(['GET','POST','PUT','DELETE'])
def userView(request):   
    if (request.method == "POST") :
        exist = User.objects.filter(username = request.POST.get("mail")).count() 
        if (exist == 0 ) :
            user = User.objects.create_user(
            username = request.POST.get("mail") ,
            password= request.POST.get("password")
            )
            rq = profile.objects.create()
            rq.firstname = request.POST.get("firstname")
            rq.lastname = request.POST.get("lastname")
            rq.phone_number = request.POST.get("phone_number")
            rq.mail = request.POST.get("mail")
            rq.dur_start = datetime.now()
            if request.POST.get("duration") == '' :
                rq.duration = 0
            else : 
                rq.duration = request.POST.get("duration")
            rq.user = user 
            rq.save() 
            return Response({
                'status' : 1 , 
                'content' : '' , 
            })
        else :
            return Response({
                    'status' : 0 , 
                    'content' : '' , 
                })
    if request.method == 'PUT' : 
        pr = profile.objects.filter(id = request.POST.get('id')) 
        if pr.count() : 

            rq = pr.first ()
            rq.firstname = request.POST.get('firstname')
            rq.lastname = request.POST.get('lastname')
            rq.duration = request.POST.get('duration')
            rq.mail = request.POST.get('mail')
            rq.phone_number = request.POST.get('phone_number')
            if request.POST.get('password') != '' : 
                sq = rq.user
                # usr = User 
                sq.set_password(request.POST.get('password'))
                sq.save()   
            if int(request.POST.get('duration')) != rq.duration : 
                rq.duration = request.POST.get('duration')
                rq.dur_start = datetime.now() 
            rq.save() 
            return Response({
            'status' : 1 , 
            'content' : '' ,
            }) 
        else : 
            return Response({
            'status' : 0 , 
            'content' : ''
           }) 
            
    if (request.method == "DELETE") :
         rq = profile.objects.filter(id=request.POST.get('id')) 
         if rq.count() : 
            rq.first().user.delete()
            return Response({
            'status' : 1 , 
            'content' : ''
           }) 
         return Response({
            'status' : 0 , 
            'content' : ''
           }) 
    return Response(-1)  

@api_view(['GET','POST','PUT','DELETE'])
def serieCroud(request): 
    if request.method == "POST" : 
        rq = serie.objects.create() 
        if (request.FILES != {}) :
            rq.icon = request.FILES['icon']
        rq.title = request.POST.get("title")
        rq.desc = request.POST.get("desc")
        rq.category = request.POST.get("category")
        rq.save() 
        return Response({
            'status' : 1 , 
            'serie' : serieSER(rq).data ,
            'quiz' : serieQuizes(rq),
        }) 
    if request.method == 'PUT' : 
        st = serie.objects.filter(id = request.POST.get('id')).count()
        if st > 0 : 
            rq = serie.objects.get(id = request.POST.get('id'))
            if (request.FILES != {}) :
                rq.icon = request.FILES['icon']
            rq.title = request.POST.get("title")
            rq.desc = request.POST.get("desc")
            rq.category = request.POST.get("category")
            rq.save() 
    
            return Response({
                'status' : 1 , 
                'quiz' : serieQuizes(rq),    
                'serie' : serieSER(rq).data   
            })
    if request.method == 'DELETE' : 
        ser = serie.objects.filter(id=request.POST.get('id'))
        if (ser.count()) : 
            ser.first().delete()   
            return Response({
                    'status' : 1 ,
                    'content' : '' ,
                })
    return Response({
            'status' : -1 , 
            'serie' : None
        })   

@api_view(['GET','POST','PUT','DELETE'])
def quizCroud(request): 
    if request.method == 'POST' : 
        count = serie.objects.filter(id = int(request.POST.get('serie')) ).count() 
        if (count > 0 and request.FILES != {} ) :    
            rq = quiz.objects.create()
            rq.serie = serie.objects.get(id= request.POST.get('serie'))
            rq.auidio_explaination = request.FILES['auidio_explaination']
            rq.audio_content = request.FILES['audio_content']
            rq.picture = request.FILES['picture']
            if 'correctAnswer' in request.FILES:
                rq.correctAnswer = request.FILES['correctAnswer']
            rq.save() 
            return Response ({   
                'status' : 1 , 
                'quiz' : quizSER(rq).data
            })
        else : 
            return Response({
                'status' : -1 , 
                'quiz' : None,
            })
    if request.method == 'PUT' : 
        rq = quiz.objects.get(id=request.POST.get('id'))
        if request.FILES != {} : 
            if (request.FILES.get('audio_content') != None) : 
                rq.audio_content = request.FILES['audio_content']
            if (request.FILES.get('auidio_explaination') != None) : 
                rq.auidio_explaination = request.FILES['auidio_explaination']
            if (request.FILES.get('picture') != None) : 
                rq.picture = request.FILES['picture']
            if (request.FILES.get('correctAnswer') != None) : 
                rq.correctAnswer = request.FILES['correctAnswer']
        rq.save()
        rs = question.objects.filter(quiz = rq) 
        questions = []
        for e in rs : 
            questions.append({
                'questions' : questionSER(e).data ,
                'answers' : answerSER(answer.objects.filter(question = e),many=True).data ,
                
            })
        return Response(({
                'status' : 1 , 
                'content' : questions  ,
                'quiz' : quizSER(rq).data ,
            }))
    if request.method == 'DELETE' : 
        ser = serie.objects.filter(id = request.POST.get('serie'))
        if (ser.count()) : 
            quiz.objects.get(id= int(request.POST.get('id'))).delete() 
            return Response(({
                'status' : 1 , 
                'content' : ''  ,
                'quiz' : serieQuizes(ser.first()) ,
            }))
    return Response(({
                'status' : -100 , 
                'quiz' : None  
            }))

@api_view(['GET','POST','PUT','DELETE'])
def clearExpImg(request): 
    if request.method == 'POST' : 
        qr = quiz.objects.get(id = request.POST.get('id'))
        qr.correctAnswer = None 
        qr.save()
        return Response(({
                    'status' : 1 , 
                    'quiz' : None  
                }))
    return Response(({
                    'status' : -100 , 
                    'quiz' : None  
                }))

@api_view(['GET','POST','PUT','DELETE'])
def answerCroud(request): 
    if request.method == 'POST' : 
        c = quiz.objects.filter(id=request.POST.get('quiz')).count()

        # rq = answer.objects.create()
        if (c > 0) :
            quizrq = quiz.objects.get(id = request.POST.get('quiz'))
            data = json.loads(request.POST.get('content'))

            for v in data  : 
                rq = question.objects.create()
                rq.quiz = quizrq 
                rq.content = v['question']
                rq.explication = v['explication']  
                rq.save()
                for k in v['answers'] : 
                    ra = answer.objects.create() 
                    ra.question = rq
                    ra.content = k['content']
                    
                    if (k['status'] == 0) : 
                        ra.status = False
                    else : 
                        ra.status = True 
                    ra.save()
            return Response({
                'status' : 1 ,
                'content' : '' ,
            })
    if request.method == 'PUT' :    
        c = quiz.objects.filter(id=request.POST.get('quiz')).count()

        if (c > 0) :
            quizrq = quiz.objects.get(id = request.POST.get('quiz'))
            data = json.loads(request.POST.get('content'))
            for d in data : 
                
                if (d['id'] == -1 ) :
                    rq = question.objects.create()
                else : 
                    rq = question.objects.get(id = d['id'])
                rq.explication = d['explication']
                rq.content = d['question']
                rq.quiz = quizrq 
                rq.save ()
                for k in d['answers'] : 
                    if (k['id'] != -1 ): 
                        aq = answer.objects.get(id = k['id']) 
                    else : 
                        aq = answer.objects.create() 
                    aq.content = k['content']
                    aq.status = k['status']
                    aq.question = rq 
                    aq.save ()
            return Response({
                'status' : 1 ,
                'content' : '' ,
            })
    if request.method == 'DELETE' : 
        if request.POST.get('type') == 'question' : 
            question.objects.get(id=request.POST.get('id')).delete() 
            return Response({
                'status' : 1 ,
                'content' : '' ,
            })
        if request.POST.get('type') == 'answer' : 
            count = answer.objects.filter(id = request.POST.get('id'))
            if count.count() > 0 :    
                count.first().delete()
                return Response({   
                    'status' : 1 ,
                    'content' : '' ,
                })
            else : 
                return Response({
                    'status' : -10 , 
                    'content' : ''  
                })
        return Response({
                'status' : -1 ,
                'content' : '' ,
            })




    return Response({
                'status' : -100 ,
                'content' : '' ,
            })

@api_view(['GET','POST','PUT','DELETE'])
def ownerProfiles(request,category): 
    if request.method == 'GET' : 
        if (category == 'GEN') : 
            proSer = profile.objects.filter()
            return Response(profileSER(proSer,many=True).data)
        elif (category == 'NJ') : 
            # proSer = profile.objects.filter(duration__isnull = True)
            pr = profile.objects.all() 
            res = []
            for a in pr : 
                if is_date_in_future(a.dur_start , a.duration) : 
                    res.append(profileSER(a).data)
            return Response(res)
        elif (category == 'BC') :
            proSer = profile.objects.filter(contacted = True)
            return Response(profileSER(proSer,many=True).data)    
        elif (category == 'NC') :    
            proSer = profile.objects.filter(contacted = False)
            return Response(profileSER(proSer,many=True).data)
        elif (category == 'series') :
            proSer = serie.objects.filter()
            return Response(renderSerie(proSer))
        elif (category == 'HOME') : 
            data = serie.objects.all().order_by('-id')[:18]
            
            return Response({
                'content' : serieSER(data,many=True).data   ,
                'categoryies' : handleCategory() , 
            })
           

    if request.method == 'POST' : 
        if (request.POST.get('state') == 'setconnect'):
            bol = False 
            if request.POST.get('inp') == 'true' : 
                bol = True   
            user = profile.objects.get(id = int(request.POST.get('id'))) 
            user.contacted =  bol
            user.save()
            return Response({
                'status' : 1 ,
            })
        if (request.POST.get('state') == 'series_test'):
            rq = serie.objects.filter(id = request.POST.get('id')) 
            if (rq.count()) : 
                rq = serie.objects.get(id = request.POST.get('id')) 
                return Response({
                    'status' : 1 ,
                    'content' : serieTest(rq) , 
                    'correct' : quizCorrAnswer(rq) , 
                })
    return Response( {   
                'status' : -10 ,
            })  

@api_view(['GET','POST','PUT','DELETE'])
def loadData(request,value):
    if request.method == 'GET' : 
        ser = serie.objects.get(id = int(value))
        return Response({
            'serieTest' : serieTest(ser) , 
            'res' : getResults(ser)
        }) 
    return Response() 

@api_view(['GET','POST','PUT','DELETE'])
def search(request): 
    if request.method == 'POST' : 
        if request.POST.get('type') == "serie" :
            rq = serie.objects.filter(title__icontains = request.POST.get('content'))
            return Response({
                'status' : 1,
                'content' : renderSerie(rq) 
            })
        if request.POST.get('type') == "quiz" :
            rq = question.objects.filter(content__icontains = request.POST.get('content'))
            
            return Response({
                'status' : 1,
                'content' : questionSER(rq,many=True).data
            })
        if request.POST.get('type') == "user" :
            getName = request.POST.get('content').split(' ')
            rq = profile.objects.filter(Q(firstname__icontains=getName[0]) | Q(lastname__icontains=getName[0]))
            if (len(getName) > 1) : 
               rq = profile.objects.filter(Q(firstname__icontains = getName[0]) | Q(lastname__icontains = getName[1]))
             
            return Response({
                'status' : 1,
                'content' : profileSER(rq,many=True).data 
            })
    return Response({})
@api_view(['GET','POST','PUT','DELETE'])
def user_login(request):
    if request.method == 'POST':
        # Get username and password from POST request  
        username = request.POST.get('username')
        password = request.POST.get('password')
        # Authenticate user
        user = authenticate(request, username=username, password=password)
        if user is not None:
            # Log in the user
            login(request, user)
            # var = profile.objects.filter(user = user)
            # status = -3
            # if (var.exists()) : 
            #     var = var.first()
            #     status = ver_userDur(var)

            return Response({'status': 1 , 'content': 'Login successful', "jwt": generate_tokens(user) })
        else:
            # Authentication failed
            return Response({'status': 0, 'content': 'Invalid username or password'})
    else:
        return Response({'status': -1, 'content': 'Invalid request method'})
    

@api_view(['GET','POST','PUT','DELETE'])
def seeRes(request): 
    if request.method == 'GET' : 
        data = json.loads(request.POST.get('results'))
        corrAnswer = 0 
        for a in data : 
            if a['answer'] != -1 : 
                rq = answer.objects.get(id=a['answer'])
                if rq.status ==  1    :
                    corrAnswer += 1 
            ques = question.objects.filter(id=a['QI']) 
            if ques.count() : 
                q = ques.first() 
                corr = answer.objects.filter(question = q,status = 1)
                a['correctAnswer'] = corr.first().id 
            else :
                a['correctAnswer'] = -1 
        qest = question.objects.filter(id=data[0]['QI']) 
        if qest.count() : 
            ser = qest.first().quiz.serie 
            cser = serieTest(ser)
        else : 
            cser = None
        return Response ({
            "totoalQ" : len(data) , 
            "correctAnswer" : corrAnswer ,      
            'correctVersion' : data , 
            'quiz' : cser ,
         })    
    return Response({
            "totoalQ" : '' ,    
            "correctAnswer" : '' 
         })  


@api_view(['GET','POST','PUT','DELETE'])
def logout(request):
    if request.method == 'POST':
        # Get the access token from the request
        access_token = request.POST.get('accessToken')
        auth = get_user_from_token(access_token)
        getAuth = False
        if (auth != None) :
            pr = profile.objects.filter(user = auth)
            if pr.exists() : 
                va = pr.first() 
                va.browser = None
                va.save()

        # Delete the access token
        # is_user_logged_in(access_token)
        return Response({'status': 1, 'content': 'Logout successful'})
    return Response({'status': -1, 'content': 'Invalid request method'})

@api_view(['GET','POST','PUT','DELETE'])
def verify_user_login(request):
    
    access_token = request.POST.get('accessToken')  # or get it from the headers
    ver = is_user_logged_in(access_token)
    ser = serie.objects.all().order_by('-id')[:5]   

    categories = handleCategory()  
    auth = get_user_from_token(access_token)
    getAuth = False
    if (auth != None) :
        pr = profile.objects.filter(user = auth)
        if pr.exists() : 
            va = pr.first() 

            if va.browser is None : 
                va.browser = request.POST.get('browserID')
                va.save()
                getAuth = is_date_in_future(va.dur_start,va.duration)
            elif va.browser != request.POST.get('browserID') : 
                getAuth = -1 
            else :
                getAuth = is_date_in_future(va.dur_start,va.duration)
    return Response({'categories':categories,'status':ver,'seriesF' : serieSER(ser,many=True).data,"auth":getAuth})

@api_view(['GET','POST','PUT','DELETE'])
def contactUs(request):
    if request.method == "POST" : 
        data = request.POST
        rq = recievingMails.objects.create()     
        rq.fullNames = data.get('fullNames')
        rq.gmail = data.get('gmail')
        rq.subject = data.get('subject')
        rq.message = data.get('message')
        rq.seen = False 
        rq.save()
        return Response({'status':1})
    if request.method == "GET" : 
       
        return Response(handleMails() )   
    if request.method == "PUT" : 
        data = request.POST
        rq = recievingMails.objects.filter(id = data.get('id'))
        if rq.count() : 
            rq.first().seen = True
            rq.first().save()
            return Response(handleMails())
    if request.method == "DELETE" : 
        data = request.POST
        rq = recievingMails.objects.filter(id = data.get('id')) 
        if rq.count() : 
            rq.first().delete()
            return Response(handleMails())
        return Response(None)
    else : 
        return Response({   
            'status' : 0 , 
                'notSeen' : '',
                'Seen' : '' , 
        })
        
@api_view(['GET','POST','PUT','DELETE'])
def checkStuff(request):
    if request.method == "POST" :
        data = request.POST
        pr = User.objects.filter(id = int(data.get('user')))
        if pr.exists():  # Check if the QuerySet is not empty
            user = pr.first()  # Get the first User object from the QuerySet
            if user.is_staff:  # Check the is_staff attribute
                return Response({'status': 1})
        return Response({'status':0})
    return Response({'status':0})

@api_view(['GET','POST','PUT','DELETE'])
def checkDuration(request):
    if request.method == "POST" : 
        data = request.POST
        pr = User.objects.filter(id = int(data.get('user')))
        if pr.exists():  # Check if the QuerySet is not empty
            user = pr.first()
            proo = profile.objects.filter(user = user)
            if proo.exists() : 
                hos = proo.first()
                ser = serie.objects.get(id = int(data.get('data')))
                return Response({
                    'status':is_date_in_future(hos.dur_start,hos.duration),
                    'serieTest' : serieTest(ser) , 
                    'res' : getResults(ser)
                }) 
        return Response({'status':-1})

    return Response()