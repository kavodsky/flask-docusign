import logging
from datetime import timedelta, datetime
from typing import List

import pytz as pytz
from docusign_esign import EnvelopeDefinition, Text, Tabs, TemplateRole, \
    ApiClient, EnvelopesApi, RecipientViewRequest
from flask import session

from .client import DSClient
from .dto import EnvelopeContext, EnvelopeUserContext


logger = logging.getLogger(__name__)


def process_envelope(config, access_token, context, account_id):
    envelope_definition = make_envelope(context)
    api_client = create_api_client(base_path=config['BASE_URL'],
                                   access_token=access_token)
    envelope_api = EnvelopesApi(api_client)
    results = envelope_api.create_envelope(
        account_id=account_id,
        envelope_definition=envelope_definition)
    return results


def get_signing_url(config, access_token, client_user_id, user_name, email,
                    envelope_id, account_id, return_url):
    api_client = create_api_client(base_path=config['BASE_URL'],
                                   access_token=access_token)
    envelope_api = EnvelopesApi(api_client)
    recipient_view_request = RecipientViewRequest(
        authentication_method="None",
        client_user_id=client_user_id,
        return_url=return_url,  # user on submit will be redirected
        user_name=user_name,  # full name
        email=email
    )
    data = envelope_api.create_recipient_view(
        account_id=account_id,
        envelope_id=envelope_id,
        recipient_view_request=recipient_view_request)
    return data.url


def make_envelope(context: EnvelopeContext):
    envelope_definition = EnvelopeDefinition(
        # requests that the envelope be created and sent.
        status=context.status,
        template_id=context.template_id
    )
    roles = make_roles(context.roles)
    envelope_definition.template_roles = roles
    return envelope_definition


def make_roles(context: EnvelopeUserContext):
    roles = []
    context = make_tabs(context)
    for user in context:
        role = TemplateRole(
            email=user.email,
            name=user.full_name,
            role_name=user.role_name,
            client_user_id=user.client_user_id,  # patient id in our system
            tabs=user.tabs
        )
        roles.append(role)
    return roles


def make_tabs(context: List[EnvelopeUserContext]):
    for user in context:
        text = Text(
            tab_label="phone_number",
            value=user.phone_number,
            locked="true",
        )
        tabs = Tabs(text_tabs=[text])
        user.tabs = tabs
    return context


def create_api_client(base_path, access_token):
    """Create api client and construct API headers"""
    api_client = ApiClient()
    api_client.host = base_path
    api_client.set_default_header(header_name="Authorization",
                                  header_value=f"Bearer {access_token}")
    return api_client


def ds_token_ok(buffer_min=10):
    """
    Checks if a token is set and won't expire in the next buffer_min(utes)
    :param buffer_min: buffer time needed in minutes
    :return: true iff the user has an access token that will be good for
    another buffer min
    """
    required = {'ds_expiration', 'ds_access_token', 'ds_account_id'}
    session_keys = set(session.keys())
    ok = session_keys.intersection(required) == required
    if ok:
        token_expiration = session.get("ds_expiration")
        buffer_starts = token_expiration - timedelta(minutes=buffer_min)
        ok = ok and buffer_starts > pytz.utc.localize(datetime.utcnow())
    return ok


def get_envelope_state(config, envelope_id, access_token, account_id):
    """

    :param config: application config object
    :param envelope_id: str
    :param access_token: str JWT token
    :param account_id: str
    :return: Envelope
             If the method is called asynchronously,
             returns the request thread.
    """
    api_client = create_api_client(base_path=config['BASE_URL'],
                                   access_token=access_token)
    envelope_api = EnvelopesApi(api_client)
    envelope = envelope_api.get_envelope(
        account_id=account_id, envelope_id=envelope_id)
    return envelope


def get_token(config, session):
    """

    :param config: application config object
    :param session: client session
    :return: str JWT token
    """
    if not ds_token_ok():
        token = _get_token(config, session)
        logger.info(f'Got DocuSign token: {token[:130]}')
    else:
        token = session.get('ds_access_token')
        logger.info(f'Using DocuSign token: {token[:130]}')
    return token


def _get_token(config, session):
    resp = DSClient.get_token(config)
    logger.info("Authenticated with DocuSign.")
    session["ds_access_token"] = resp["access_token"]
    session["ds_refresh_token"] = resp["refresh_token"]
    expires_sec_from_now = timedelta(seconds=int(resp["expires_in"]))
    session["ds_expiration"] = datetime.utcnow() + expires_sec_from_now
    get_account_id(config, resp["access_token"])
    return session.get('ds_access_token')


def get_account_id(config, token):
    account_id = session.get("ds_account_id")
    if not account_id:
        # Request to API to get the user information
        response = DSClient.get_user(config, token)
        accounts = response.get("accounts")
        if not accounts:
            raise NoAccountException
        # Find the account...
        account = next((a for a in accounts if a["is_default"]), None)
        if not account:
            # Every user should always have a default account
            raise NoAccountException

        # Save the account information
        base_uri_suffix = config['BASE_URI_SUFFIX']
        session["ds_account_id"] = account["account_id"]
        session["ds_account_name"] = account["account_name"]
        session["ds_base_path"] = account["base_uri"] + base_uri_suffix
    return session.get("ds_account_id")


class NoAccountException(Exception):

    def __init__(self, message='No default account was found'):
        super().__init__(message)


def clear_token():
    # Token is stored in two places - DSClient instance and user session
    DSClient.destroy()
    if 'ds_access_token' in session.keys():
        session.pop('ds_access_token')

