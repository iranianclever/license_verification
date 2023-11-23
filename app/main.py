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


@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    """ Creates database if method is post otherwise shows the homepage with some stats see import_database_from_excel() for more details on database creation """
    # if request.method == 'POST':
    #     if 'file' not in request.files:
    #         flash('No file part', 'danger')
    #         return redirect(request.url)
    #     file = request.files['file']
    #     # if user does not select file, browser also
    #     # submit an empty part without filename
    #     if file.filename == '':
    #         flash('No selected file', 'danger')
    #         return redirect(request.url)
    #     if file and allowed_file(file.filename):
    #         filename = secure_filename(file.filename)
    #         filename.replace(' ', '_')
    #         file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    #         file.save(file_path)
    #         subprocess.Popen(['python', 'import_db.py', file_path])
    #         flash(
    #             'File uploaded. Will be imported soon. Follow from DB Status page.', 'info')
    #         return redirect('/')

    # # Init mysql connection
    # db = get_database_connection()

    return render_template('index.html')


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



# @app.route(f'/v1/{config.REMOTE_ALL_API_KEY}/check_one_serial/<serial>', methods=['GET'])
# def check_one_serial_api(serial):
#     """ To check whether a serial number is valid or not using api caller should use something like /v1/ABCDSECRET/check_one_serial/AA10000 answer back json which is status = DOUBLE, FAILURE, ON, NOT-FOUND """
#     status, answer = check_serial(serial)
#     ret = {'status': status, 'answer': answer}
#     return jsonify(ret), 200


# @app.route('/check_one_serial', methods=['POST'])
# @login_required
# def check_one_serial():
#     """ To check whether a serail number is valid or not """
#     serial_to_check = request.form['serial']
#     status, answer = check_serial(serial_to_check)
#     flash(f'{status} - {answer}', 'info')

#     return redirect('/')


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


@app.route('/v1/ok')
def health_check():
    """ Will return message: OK when called. for monitoring systems. """
    ret = {'message': 'ok'}
    return jsonify(ret), 200


def get_database_connection():
    return MySQLdb.connect(host=config.MYSQL_HOST, user=config.MYSQL_USERNAME,
                           passwd=config.MYSQL_PASSWORD, db=config.MYSQL_DB_NAME, charset='utf8')

@app.errorhandler(404)
def page_not_found(error):
    """ Redirect to 404 page in page not found status. """
    return render_template('404.html'), 404


def send_sms(receptor, message):
    """ This function will get a MSISDN and a message, then uses KaveNegar to send sms.  """
    url = f'https://api.kavenegar.com/v1/{config.API_KEY}/sms/send.json'
    data = {'message': message, 'receptor': receptor}
    response = requests.post(url, data)
    print(
        f'message *{message}* send to receptor: {receptor}. status code is {response.status_code}')


# @app.route(f'/v1/{CALL_BACK_TOKEN}/process', methods=['POST'])
# def process():
#     """ This is a callback from curl requests. will get sender and message and will check if it is valid, then answers back.
#     This is secured by 'CALL_BACK_TOKEN' in order to avoid mal-intended calls. """
#     # Note: You need to call back token to send request (post) to process function
#     data = request.form
#     sender = data['from']
#     message = data['message']

#     status, answer = check_serial(message)

#     # Init mysql connection
#     db = get_database_connection()

#     cur = db.cursor()

#     log_new_sms(status, sender, message, answer, cur)

#     db.commit()
#     db.close()

#     send_sms(sender, answer)
#     ret = {'message': 'processed!'}
#     return jsonify(ret), 200


# def create_sms_table():
#     """ Creates PROCESSED_SMS table on database if it's not exists. """
#     # Init mysql connection
#     db = get_database_connection()
#     cur = db.cursor()

#     try:
#         cur.execute("CREATE TABLE IF NOT EXISTS PROCESSED_SMS (status ENUM('OK', 'FAILURE', 'DOUBLE', 'NOT-FOUND'), sender CHAR(20), message VARCHAR(400), answer VARCHAR(400), date DATETIME, INDEX(date, status));")
#         db.commit()
#     except Exception as e:
#         flash(f'Error creating PROCESSED_SMS table; {e}', 'danger')

#     db.close()


if __name__ == '__main__':
    # create_sms_table()
    app.run('0.0.0.0', 5000, debug=True)
