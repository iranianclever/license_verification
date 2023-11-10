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


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit('20 per minute')
def login():
    """ User login: only for admin user (System has no other user than admin)
    Note: there is a 10 tries per minute limitation to admin login to avoid minimize password factoring """
    if current_user.is_authenticated:
        return redirect('/')
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if password == config.PASSWORD and username == config.USERNAME:
            login_user(user)
            return redirect('/')
        else:
            return abort(401)
    else:
        return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """ Logs out the admin user """
    logout_user()
    flash('Logged out', 'success')
    return redirect('/login')


# handle login failed
@app.errorhandler(401)
def unauthorized(error):
    """ Handling login failures """
    flash('Login problem', 'danger')
    return redirect('/login')


# callback to reload the user object
@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


@app.errorhandler(404)
def page_not_found(error):
    """ Redirect to 404 page in page not found status. """
    return render_template('404.html'), 404


@app.route('/v1/ok')
def health_check():
    """ Will return message: OK when called. for monitoring systems. """
    ret = {'message': 'ok'}
    return jsonify(ret), 200


@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    """ Creates database if method is post otherwise shows the homepage with some stats see import_database_from_excel() for more details on database creation """
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filename.replace(' ', '_')
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            subprocess.Popen(['python', 'import_db.py', file_path])
            flash(
                'File uploaded. Will be imported soon. Follow from DB Status page.', 'info')
            return redirect('/')

    return render_template('index.html')


if __name__ == '__main__':
    app.run('0.0.0.0', 5000, debug=True)