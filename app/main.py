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