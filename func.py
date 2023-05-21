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
from py_zipkin import Encoding #import Zipkin package
from py_zipkin.zipkin import zipkin_span #import Zipkin package
from transport import http_transport #import Zipkin transport

@zipkin_span(service_name='statusGetFile', span_name='statusGetFile')
def handler(ctx, data: io.BytesIO = None):
    with zipkin_span(
            service_name="Status: Load File", #You can change it as you need
            span_name=json.loads(data.getvalue()).get("objectID"), #You can change it as you need
            transport_handler=http_transport, #zipkin transport, will use it to upload trace data to OCI APM
            encoding = Encoding.V2_JSON,
            binary_annotations = {"get":data.getvalue()}, #Custom tag
            sample_rate=100 # this is optional and can be used to set custom sample rates
    ):

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

            details = oci.object_storage.models.CreatePreauthenticatedRequestDetails(name=objectID, access_type="ObjectRead", object_name=objectID, time_expires=expiresAt)

            preauth = object_storage.create_preauthenticated_request(namespace_name=namespace, bucket_name="data", create_preauthenticated_request_details=details)
            preauthstr = str(preauth.data)

            auth = clientID + ":" + secretID
            auth_bytes = auth.encode("ascii")
            auth_base64_bytes = base64.b64encode(auth_bytes)
            auth_base64_message = auth_base64_bytes.decode("ascii")

            headers = {"Authorization": "Basic " + auth_base64_message, "Content-Type": "application/x-www-form-urlencoded"}

            scope = "xxxxxxxxxxxxxxxxxxxx.apigateway.us-ashburn-1.oci.customer-oci.com/super-scope"
            grant_type = "client_credentials"

            body = {"scope": scope, "grant_type": grant_type}

            url_post = "https://idcs-xxxxxxxxxxxxxxxxxxxxxxx.identity.oraclecloud.com/oauth2/v1/token"
            post_response = requests.post(url_post, headers=headers, data=body)

            jwtTokenDecoded = jwt.decode(post_response.json()['access_token'], options={"verify_signature": False})

            #return response.Response(
            #    ctx,
            #    status_code=200,
            #    response_data=json.dumps({"active": True, "principal": "foo", "scope": "bar", "clientId": "1234", "expiresAt": expiresAt, "context": {"username": "wally", "token": post_response.json()['access_token'], "jwtTokenDecoded": jwtTokenDecoded, "object": objstr}})
            # )
            return response.Response(
                ctx,
                status_code=200,
                response_data=json.dumps({"active": True, "principal": "foo", "scope": "bar", "clientId": "1234", "expiresAt": expiresAt, "context": {"username": "wally", "token": post_response.json()['access_token'], "jwtTokenDecoded": jwtTokenDecoded, "objectID": preauthstr}})
            )

        except (Exception, ValueError) as ex:
            logging.getLogger().info('error parsing json payload: ' + str(ex))
            pass

        return response.Response(
            ctx,
            status_code=401,
            response_data=json.dumps({"active": False, "wwwAuthenticate": "API-key"})
        )


