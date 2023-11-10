import datetime
import os
import re
import time
import subprocess
from textwrap import dedent

import requests
from flask import (
    Flask,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from werkzeug.utils import secure_filename

import config
import MySQLdb
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from pandas import read_excel

# Sample flask object
app = Flask(__name__)

# Create limiter to prevent brute force
limiter = Limiter(app=app, key_func=get_remote_address,
                  storage_uri="memory://")

# Constant configs
MAX_FLASH = 10
UPLOAD_FOLDER = config.UPLOAD_FOLDER
ALLOWED_EXTENSIONS = config.ALLOWED_EXTENSIONS
CALL_BACK_TOKEN = config.CALL_BACK_TOKEN

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# flask-login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'danger'


def allowed_file(filename):
    """ Check the extension of the passed filename to be in the allowed extensions """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# A secure key to protect app
app.config.update(SECRET_KEY=config.SECRET_KEY, DEBUG=True)


class User(UserMixin):
    """ A minimal and singleton user class used only for administrative tasks """

    def __init__(self, id):
        """ Constructor initialize user id """
        self.id = id

    def __repr__(self):
        return "%d" % (self.id)


user = User(0)