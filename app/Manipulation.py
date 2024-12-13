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
    refresh = RefreshToken.for_user(user)
    return {
        "access": str(refresh.access_token),
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

        # If user is found and the token is valid, return True
        return True
    except AuthenticationFailed:
        # If token is invalid or expired, return False
        return False
    
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

