import logging
from datetime import timedelta, datetime

from .api import get_token, get_account_id, process_envelope, get_signing_url, clear_token, get_envelope_state
from .client import DSClient
from .dto import EnvelopeUserContext, EnvelopeContext

logger = logging.getLogger(__name__)


def get_signing_redirect_url(config, request_data):
    default_callback_url = 'http://localhost:8080'
    remote_addr = request_data.headers.get('Origin', '(origin not set)')
    # remote_addr = request_data.headers.get('HOST')
    logger.info(f'Request from {remote_addr}')
    if remote_addr.startswith(('http://127.0.0.1', 'http://0.0.0.0')):
        logger.info('Returning default redirect URL.')
        return default_callback_url
    else:
        logger.info(f'Setting DocuSign redirect URL : {remote_addr}')
        return (f'{remote_addr}/{config["SIGNING_URL_CALLBACK_PATH"]}'
                if remote_addr in config['SIGNING_URL_CALLBACK_ALLOWED_DOMAINS']
                else default_callback_url)


def get_docusign_signing_url(config, session, context, return_url):
    status = 200
    try:
        token = get_token(config, session)
        account_id = get_account_id(config, token)
        results = process_envelope(config,
                                   token,
                                   context,
                                   account_id)
        envelope_id = results.envelope_id
        logger.info(f'Got envelope: {envelope_id}')
        # Assuming we have only one person to sign
        url = get_signing_url(config=config,
                              access_token=token,
                              client_user_id=context.roles[0].client_user_id,
                              user_name=context.roles[0].full_name,
                              email=context.roles[0].email,
                              envelope_id=envelope_id,
                              account_id=account_id,
                              return_url=return_url)
        logger.info(f'Document sign URL: {url}')
        msg = {'url': url, 'envelopeId': envelope_id}
    except Exception as e:
        logger.exception(f'Error during DocuSign sing url creation: {e}')
        # Old token can cause a request to fail. Clear it to avoid next error.
        clear_token()
        msg = 'Exception during signing'
        status = 500
    return msg, status


def check_envelope(config, session, envelope_id):
    try:
        token = get_token(config, session)
        account_id = get_account_id(config, token)
        envelope = get_envelope_state(config=config,
                                      envelope_id=envelope_id,
                                      access_token=token,
                                      account_id=account_id)
        response = {'sent_date_time': envelope.sent_date_time,
                    'status': envelope.status,
                    'status_changed_date_time': envelope.status_changed_date_time,
                    'envelope_id': envelope.envelope_id}
        state = 200
    except Exception as e:
        clear_token()
        logger.exception(e)
        response = 'Cannot get envelope state.'
        state = 500
    return response, state


def create_envelope(config, request, session):
    data = request.json
    return_url = get_signing_redirect_url(config, request)
    role_context = EnvelopeUserContext(**data)
    context = EnvelopeContext(
        roles=[role_context], template_id=config['DS_TEMPLATE_ID'])
    msg, status = get_docusign_signing_url(config=config,
                                           session=session,
                                           context=context,
                                           return_url=return_url)
    if status == 500:
        # User cookies can store outdated data which can cause previous request
        # to fail, that's why we do second request on failure.
        logger.info('Previous DocuSign sign request failed trying second time.')
        msg, status = get_docusign_signing_url(config=config,
                                               session=session,
                                               context=context,
                                               return_url=return_url)
    return msg, status


def set_client_cookie(config, session):
    resp = DSClient.get_token()
    session["ds_access_token"] = resp["access_token"]
    session["ds_refresh_token"] = resp["refresh_token"]
    expires_sec_from_now = timedelta(seconds=int(resp["expires_in"]))
    session["ds_expiration"] = datetime.utcnow() + expires_sec_from_now
    get_account_id(config, resp["access_token"])