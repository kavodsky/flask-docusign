import json
import math
from time import time

import jwt
from docusign_esign import ApiClient, OAuth, OAuthToken
from docusign_esign.client.api_exception import ArgumentException, ApiException


class DSPatchApiClient(ApiClient):

    def request_jwt_user_token(self, client_id, user_id, oauth_host_name,
                               private_key_bytes, expires_in,
                               scopes=(OAuth.SCOPE_SIGNATURE,)):
        """
        Request JWT User Token
        :param client_id: DocuSign OAuth Client Id(AKA Integrator Key)
        :param user_id: DocuSign user Id to be impersonated
        :param oauth_host_name: DocuSign OAuth host name
        :param private_key_bytes: the byte contents of the RSA private key
        :param expires_in: number of seconds remaining before the JWT
         assertion is considered as invalid
        :param scopes: Optional. The list of requested scopes may include
        (but not limited to) You can also pass any
        advanced scope.
        :return: OAuthToken object
        """
        if not private_key_bytes:
            raise ArgumentException("Private key not supplied or is invalid!")
        if not user_id:
            raise ArgumentException("User Id not supplied or is invalid!")
        if not oauth_host_name:
            raise ArgumentException("oAuthBasePath cannot be empty")

        now = math.floor(time())
        later = now + (expires_in * 1)
        claim = {"iss": client_id, "sub": user_id, "aud": oauth_host_name,
                 "iat": now, "exp": later,
                 "scope": " ".join(scopes)}
        token = jwt.encode(payload=claim,
                           key=private_key_bytes,
                           algorithm='RS256')

        response = self.request(
            "POST",
            "https://" + oauth_host_name + "/oauth/token",
            headers=self.sanitize_for_serialization(
                {"Content-Type": "application/x-www-form-urlencoded"}),
            post_params=self.sanitize_for_serialization(
                {"assertion": token, "grant_type": OAuth.GRANT_TYPE_JWT}))

        response_data = json.loads(response.data)

        if 'token_type' in response_data and 'access_token' in response_data:
            self.set_default_header(
                "Authorization",
                f"{response_data['token_type']} {response_data['access_token']}"
            )
        else:
            raise ApiException(
                status=response.status,
                reason=f"Error while requesting server, received a non"
                       f" successful HTTP code {response.status} with "
                       f"response Body: {response.data}")

        return self.deserialize(response=response, response_type=OAuthToken)