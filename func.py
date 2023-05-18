import io
import json
import logging
import datetime
import jwt
import requests
import base64
import oci

from datetime import timedelta
from fdk import response

def handler(ctx, data: io.BytesIO = None):
    auth_token = "invalid"
    token = "invalid"
    apiKey = "invalid"
    expiresAt = (datetime.datetime.utcnow() + timedelta(seconds=60)).replace(tzinfo=datetime.timezone.utc).astimezone().replace(microsecond=0).isoformat()

    config = oci.config.from_file("config")
    object_storage = oci.object_storage.ObjectStorageClient(config)
    namespace = object_storage.get_namespace().data

    try:
        auth_token = json.loads(data.getvalue())
        secretID = auth_token.get("secretID")
        clientID = auth_token.get("clientID")
        objectID = auth_token.get("objectID")

        get_obj = object_storage.get_object(namespace, "data", objectID)
        objb64 = base64.b64encode(get_obj.data.content)
        objstr = objb64.decode('utf-8')

        auth = clientID + ":" + secretID
        auth_bytes = auth.encode("ascii")
        auth_base64_bytes = base64.b64encode(auth_bytes)
        auth_base64_message = auth_base64_bytes.decode("ascii")

        headers = {"Authorization": "Basic " + auth_base64_message, "Content-Type": "application/x-www-form-urlencoded"}

        scope = "xxxxxxxxxxxxxxxxxxxxxx.apigateway.us-ashburn-1.oci.customer-oci.com/super-scope"
        grant_type = "client_credentials"

        body = {"scope": scope, "grant_type": grant_type}

        url_post = "https://idcs-xxxxxxxxxxxxxxxxxxxxxxx.identity.oraclecloud.com/oauth2/v1/token"
        post_response = requests.post(url_post, headers=headers, data=body)

        jwtTokenDecoded = jwt.decode(post_response.json()['access_token'], options={"verify_signature": False})

        return response.Response(
            ctx,
            status_code=200,
            response_data=json.dumps({"active": True, "principal": "foo", "scope": "bar", "clientId": "1234", "expiresAt": expiresAt, "context": {"username": "wally", "token": post_response.json()['access_token'], "jwtTokenDecoded": jwtTokenDecoded, "object": objstr}})
        )

    except (Exception, ValueError) as ex:
        logging.getLogger().info('error parsing json payload: ' + str(ex))
        pass

    return response.Response(
        ctx,
        status_code=401,
        response_data=json.dumps({"active": False, "wwwAuthenticate": "API-key"})
    )


