import jwt
from django.http import HttpResponseForbidden
from django.conf import settings
from api.models import User
secret=settings.JWT_SECRET

class JWTAuthenticationMiddleware:
    def __init__(self,get_response):
        self.get_response=get_response

    def __call__(self,request):
        if request.path=='/job/post/':
            token=request.COOKIES.get('jwt_token')
            if token:
                try:
                    payload=jwt.decode(token,secret,algorithms=["HS256"])
                    if(payload.get("account_type")=="company"):
                        #request.user=payload
                        pass
                    else:
                        return HttpResponseForbidden("Access denied")
                except jwt.ExpiredSignatureError:
                    return HttpResponseForbidden("Token has expired")
                except jwt.DecodeError:
                    return HttpResponseForbidden("Invalid token")
            else:
                return HttpResponseForbidden("Please Login First")
        if request.path=='/job/apply/' or request.path=='/job/list/'  or request.path=='/application/cancel/' or request.path=='/application/list/' :
            token=request.COOKIES.get('jwt_token')
            if token:
                try:
                    payload=jwt.decode(token,secret,algorithms=["HS256"])
                    if(payload.get("account_type")=="job_seeker"):
                        #request.user=payload
                        pass
                    else:
                        return HttpResponseForbidden("Access denied")
                except jwt.ExpiredSignatureError:
                    return HttpResponseForbidden("Token has expired")
                except jwt.DecodeError:
                    return HttpResponseForbidden("Invalid token")
            else:
                return HttpResponseForbidden("Please Login First")
        
            
        response=self.get_response(request)
        return response
                    