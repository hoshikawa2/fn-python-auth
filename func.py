import io
import json
import logging
import datetime
import jwt

from datetime import timedelta
from fdk import response

def handler(ctx, data: io.BytesIO = None):
    auth_token = "invalid"
    token = "invalid"
    apiKey = "invalid"
    expiresAt = (datetime.datetime.utcnow() + timedelta(seconds=60)).replace(tzinfo=datetime.timezone.utc).astimezone().replace(microsecond=0).isoformat()
    
    try:
        auth_token = json.loads(data.getvalue())
        token = auth_token.get("token")

        jwtTokenDecoded = jwt.decode(token, options={"verify_signature": False})
        
        app_context = dict(ctx.Config())
        apiKey = app_context['FN_API_KEY']
        
        return response.Response(
            ctx, 
            status_code=200, 
            response_data=json.dumps({"active": True, "principal": "foo", "scope": "bar", "clientId": "1234", "expiresAt": expiresAt, "context": {"username": "wally", "jwtTokenDecoded": jwtTokenDecoded}})
         )
    
    except (Exception, ValueError) as ex:
        logging.getLogger().info('error parsing json payload: ' + str(ex))
        pass
    
    return response.Response(
        ctx, 
        status_code=401, 
        response_data=json.dumps({"active": False, "wwwAuthenticate": "API-key"})
    )


