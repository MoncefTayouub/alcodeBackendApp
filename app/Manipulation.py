from .models import * 
from .serializable import * 
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed


def serieQuizes (serie) : 
    qz = quiz.objects.filter(serie = serie) 
    quizes = []
    for q in qz :
        s = question.objects.filter(quiz = q)
        quest = ''
        if (s.count()) : 
            quest = s.first().content
        quizes.append({
            'quizId' : q.id ,
            'question' : quest ,  
            'quizOB' : quizSER(q).data
        })
    return quizes


def renderSerie (series) : 
    res = serieSER(series,many=True).data
    i = 0 
    for a in series : 
        res[i]['childs'] = quiz.objects.filter(serie =  a).count()
        i += 1
    return res 

def serieTest (serie) : 

    qz = quiz.objects.filter(serie = serie)
    SER = quizSER(qz, many=True).data 
    i = 0 
    
    for a in qz : 
        rq = question.objects.filter(quiz = a )
        label = []
        for f in rq : 
            aq = answer.objects.filter(question = f ) 
            label.append({
                'question' : questionSER(f).data ,
                'answers' : answerSERsec(aq,many=True).data 
            })
        SER[i]['content'] = label
        i += 1   
    return SER 

    

def generate_tokens(user):
    # Generate the refresh token
    refresh = RefreshToken.for_user(user)

    # Set the expiration time for the access token to 1 day (24 hours)
    access_token = refresh.access_token
    access_token.set_exp(lifetime=timedelta(days=1))  # 1 day expiration

    return {
        "access": str(access_token),
        "refresh": str(refresh),
        "user_id": user.id,
        "username": user.username,
    }

from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth import get_user_model

User = get_user_model()

def verify_user_login(token_data):
    """
    Verifies if the user can be logged in based on the provided token data.

    :param token_data: Dictionary containing access_token, refresh_token, user_id, and username.
    :return: Boolean indicating if the user can be logged in or raises an error.
    """
    access_token = token_data.get("access")
    user_id = token_data.get("user_id")

    if not access_token or not user_id:
        raise AuthenticationFailed("Invalid token data provided")

    try:
        # Decode the access token
        validated_token = AccessToken(access_token)

        # Check if the user ID from the token matches the user_id in the token data
        if validated_token["user_id"] != str(user_id):
            raise AuthenticationFailed("User ID mismatch")

        # Check if the user exists
        user = User.objects.get(id=user_id)
        
        # Optionally, check if the user is active (if that's part of your logic)
        if not user.is_active:
            raise AuthenticationFailed("User is inactive")
        
        return True  # User is authenticated and valid

    except Exception as e:
        # Catch any exceptions, including expired tokens or invalid user
        raise AuthenticationFailed(f"Authentication failed: {str(e)}")

def is_user_logged_in(access_token):
    """
    Checks if a user can be logged in using the provided access token.
    
    :param access_token: The access token to validate
    :return: True if user is authenticated, False otherwise
    """
    # Initialize the JWT Authentication class
    authentication = JWTAuthentication()

    try:
        # Attempt to validate the token
        validated_token = authentication.get_validated_token(access_token)
        
        # If the token is valid, get the user
        user = authentication.get_user(validated_token)
        # if user and user.is_staff:
        #     return 2
        

        # If user is found and the token is valid, return True
        return 1
    except AuthenticationFailed:
        # If token is invalid or expired, return False
        return 0
    
def handleMails () : 
    rq = recievingMails.objects.filter(seen = False)
    r1 = recievingMails.objects.filter(seen = True)
    return {
        'status' : 1 , 
        'notSeen' : recievingMailsSER(rq , many = True).data , 
        'Seen' : recievingMailsSER(r1 , many = True).data , 
    }

def getResults (serie) : 
    if serie : 
        rq = quiz.objects.filter(serie = serie)
        res = []
        for a in rq :  
            aq = question.objects.filter(quiz=a ) 
            for q in aq : 
                ans = answer.objects.filter(question = q , status=1) 
                ids = []
                for n in ans : 
                    ids.append(n.id)
                res.append({'answer':ids , 'Qc' : q.content ,'QI':q.id})

        return res 
    return []

from datetime import datetime, timedelta , date

def validate_date(date_string):

    formats = ["%Y-%m-%d", "%m/%d/%Y", "%d-%m-%Y"]  # List of accepted formats
    for fmt in formats:
        try:
            return datetime.strptime(date_string, fmt)
        except ValueError:
            continue
    return None
def date_to_seconds(date_input):
    if isinstance(date_input, datetime):
        return int(date_input.timestamp())
    elif isinstance(date_input, date):
        datetime_input = datetime.combine(date_input, datetime.min.time())
        return int(datetime_input.timestamp())
    else:
        valid_date = validate_date(date_input)
        if valid_date:
            return int(valid_date.timestamp())
    return None



def is_date_in_future (dur_start , duration) :
    today = date.today() 
    if (date_to_seconds(dur_start) + duration*24*60*60) > date_to_seconds(today) : 
        return 1
    return 0
    
def ver_userDur (pr):
    if isinstance(pr,profile) : 
        
        return is_date_in_future(pr.dur_start,pr.duration)
    return -1

def notSubAcc ():
    pr = profile.objects.all() 
    res = []
    for a in pr : 
        # if a.duration : 
        if is_date_in_future(a.dur_start , a.duration) : 
            res.append(profileSER(a).data)
        return res 
    return []




import jwt
from django.contrib.auth.models import User
from django.conf import settings

def get_user_from_token(token):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get('user_id')
        user = User.objects.filter(id=int(user_id))
        
        return user.first()
    except jwt.ExpiredSignatureError:
        # Token has expired
        return None
    except jwt.DecodeError:
        # Token is invalid
        return None
    except User.DoesNotExist:
        # User not found
        return None

def quizCorrAnswer (ser) :
    qz = quiz.objects.filter(serie = ser)
    resQz = []
    for b  in qz : 
        qq = question.objects.filter(quiz = b)
        for a in qq : 
            res = []
            ans = answer.objects.filter(question = a , status = 1)
            for n in ans : 
                res.append(n.id)
            resQz.append({'qzId':b.id,'qId':a.id , 'correctAnswers':res})    
    return resQz

def getCorrectAnswers (qz) : 
    # if isinstance(qz,quiz) : 
    #     return None
    quee = question.objects.filter(quiz = qz) 
    res = []    
    for a in quee : 
        line = []
        answers = answer.objects.filter(question = a , status = 1 )


        for m in answers : 
            line.append(int(m.id)) 
        res.append({'QI':int(a.id), 'CA' : line})
        # res.append({'QI':int(a.id),'explication':int(a.explication) , 'CA' : line})
    return {'QZID':int(qz.id),'QCI':str(qz.correctAnswer),'auidio_explaination':str(qz.auidio_explaination),'content':res}

def handleseriecoorr (se) : 
    qz = quiz.objects.filter(serie = se) 
    res = [] 
    for a in qz : 
        dd = getCorrectAnswers(a) 
        if dd : 
            res.append(dd)
    return res 


def handleCategory () : 
    res = []
    for a in range(0,5):
        res.append(serie.objects.filter(category = a).count()>0)
    return res



def testAuth (access_token,browserID): 

    ver = is_user_logged_in(access_token)
    ser = serie.objects.all().order_by('-id')[:5]   

    categories = handleCategory()  
    auth = get_user_from_token(access_token)
    getAuth = False
    if (auth != None) :
        pr = profile.objects.filter(user = auth)  
        if pr.exists() : 
            va = pr.first() 
            print('-------',va.browser,va.browser is None,browserID)
            if va.browser is None : 
                va.browser = browserID
                va.save()
                getAuth = is_date_in_future(va.dur_start,va.duration)
            elif va.browser != browserID :
                getAuth = -1 
            else :
                getAuth = is_date_in_future(va.dur_start,va.duration)
            print('getAuth',getAuth)
    return ({'status':ver,"auth":getAuth})

# 'seriesF' : serieSER(ser,many=True).data,'categories':categories,