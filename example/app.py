#!/usr/bin/env python
import logging

from flask import Flask

from docusign_blueprint import ds
from config import get_config_object


app = Flask(__name__)
app.config.from_object(get_config_object())

logger = logging.getLogger(__name__)


app.register_blueprint(ds,
                       url_prefix=f'{app.config["APPLICATION_ROOT"]}/ds')


# local development ($ python main.py)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
