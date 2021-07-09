import logging

from flask import Blueprint, jsonify, session, redirect, request, current_app

from flask_docusign.calls import check_envelope, create_envelope, set_client_cookie

from config import DefaultConfig


ds = Blueprint('ds', __name__)
conf = DefaultConfig()
logger = logging.getLogger(__name__)


@ds.route('/', methods=['POST'])
def docusign_create_envelope():
    config = current_app.config
    msg, status = create_envelope(config, request, session)
    return jsonify({'msg': msg}), status


@ds.route("/callback")
def ds_callback():
    """
    Save the token information in session.
    Call api to get user's information if it doesn't present
    """
    # Save the redirect eg if present
    config = current_app.config
    set_client_cookie(config, session)
    return redirect('docusign_create_envelope')


@ds.route("/check/<envelope_id>", methods=['GET'])
def ds_check_envelope(envelope_id):
    state = 401
    if not len(envelope_id):
        return jsonify({'msg': 'Please verify your envelope id.'}), state
    config = current_app.config
    response, state = check_envelope(config, session, envelope_id)
    return jsonify({'msg': response}), state
