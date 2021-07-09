import json
import logging

import requests
from flask import request, redirect, url_for
from docusign_esign import OAuth
from docusign_esign.client.api_exception import ApiException

from .patch import DSPatchApiClient

logger = logging.getLogger(__name__)


class DSClient:
    ds_app = None

    @classmethod
    def _init(cls, config):
        cls._jwt_auth(config)

    @classmethod
    def _jwt_auth(cls, config):
        """JSON Web Token authorization"""
        api_client = DSPatchApiClient()
        api_client.set_base_path(config['BASE_URL'])
        # Catch IO error
        private_key = cls._get_private_key(config)
        try:
            cls.ds_app = api_client.request_jwt_user_token(
                client_id=config['DS_CLIENT_ID'],
                user_id=config['DS_IMPERSONATED_USER_ID'],
                oauth_host_name=config['DS_AUTHORIZATION_SERVER'],
                private_key_bytes=private_key,
                expires_in=3600,
                scopes=(OAuth.SCOPE_SIGNATURE, OAuth.SCOPE_IMPERSONATION)
            )
            return cls.ds_app
        except ApiException as err:
            body = err.body.decode('utf8')
            # Grand explicit consent for the application
            if "consent_required" in body:
                logger.error(body)
                return redirect(cls.get_consent_url(config=config))
            else:
                process_error(err)

    @classmethod
    def destroy(cls):
        cls.ds_app = None

    @staticmethod
    def _get_private_key(config):
        cert = config['PRIVATE_KEY_FILE']
        return bytes(cert.replace('\\n', '\n'), encoding='utf-8')

    @classmethod
    def login(cls, config):
        return cls._jwt_auth(config)

    @classmethod
    def get_token(cls, config):
        resp = cls.get(config).to_dict() if cls.get(config) else None
        if resp is None or resp.get("access_token") is None:
            return "Access denied: reason=%s error=%s resp=%s" % (
                request.args["error"],
                request.args["error_description"],
                resp
            )
        return resp

    @classmethod
    def get_user(cls, config, access_token):
        """Make request to the API to get the user information"""
        # Determine user, account_id, base_url by calling OAuth::getUserInfo
        # See https://developers.docusign.com/esign-rest-api/guides/authentication/user-info-endpoints
        url = 'https://' + config['DS_AUTHORIZATION_SERVER'] + "/oauth/userinfo"
        auth = {"Authorization": "Bearer " + access_token}
        response = requests.get(url, headers=auth).json()
        return response

    @classmethod
    def get_consent_url(cls, config):
        consent_scopes = " ".join((OAuth.SCOPE_SIGNATURE,
                                   OAuth.SCOPE_IMPERSONATION))
        redirect_uri = config['APP_URL'] + url_for("ds.ds_callback")
        consent_url = f"https://{config['DS_AUTHORIZATION_SERVER']}" \
                      f"/oauth/auth?response_type=code&" \
                      f"scope={consent_scopes}&" \
                      f"client_id={config['DS_CLIENT_ID']}&" \
                      f"redirect_uri={redirect_uri}"
        return consent_url

    @classmethod
    def get(cls, config):
        if not cls.ds_app:
            cls._init(config)
        return cls.ds_app


def process_error(err):
    error_body_json = err and hasattr(err, "body") and err.body
    # we can pull the DocuSign error code and message from the response body
    error_body = json.loads(error_body_json)
    error_code = (error_body and "errorCode" in error_body
                  and error_body["errorCode"])
    error_message = (error_body and "message" in error_body
                     and error_body["message"])
    logger.error(f'Got error during authentication grant: {error_message}. '
                 f'Error code: {error_code}')
