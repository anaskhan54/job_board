import jwt
from django.http import HttpResponseForbidden
from django.conf import settings
secret=settings.JWT_SECRET

class JWTAuthenticationMiddleware:
    def __init__(self,get_response):
        self.get_response=get_response

    def __call__(self,request):
        if request.path=='/dashboard':
            token=request.COOKIES.get('jwt_token')
            if token:
                try:
                    payload=jwt.decode(token,secret,algorithms=["HS256"])
                    if(payload.get("account_type")=="company"):
                        request.user=payload
                    else:
                        return HttpResponseForbidden("Access denied")
                except jwt.ExpiredSignatureError:
                    return HttpResponseForbidden("Token has expired")
                except jwt.DecodeError:
                    return HttpResponseForbidden("Invalid token")
            
        response=self.get_response(request)
        return response
                    