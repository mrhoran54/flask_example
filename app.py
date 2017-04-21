#!/usr/bin/python
#from flask import Flask, Response, render_template, url_for, send_from_directory, session, g

import os
#
from flask import url_for, request, session, redirect, jsonify, render_template, send_from_directory
from flask_oauth import OAuth
##
from urllib import quote
from urllib import urlencode
import flask_login as flask_login
##
###for login
from flask_wtf import Form
from wtforms import StringField, BooleanField
from wtforms.validators import DataRequired
from flask_googlemaps import GoogleMaps
#from flask_googlemaps import Map

from flask import Flask
app = Flask(__name__)

app.secret_key = "345435dsmd.35##3f90ec8062a9e91707e70c2edb919f7e8236ddb5"

app.config.update(
    DEBUG = True,
)

LOGIN_REDIRECT_URL =  "mapview"
CSRF_ENABLED = True

# setting up the database
from pymongo import MongoClient
client = MongoClient('localhost', 27017)
# make a database called saved
db = client.saved
# yelp search database
saved_search = db.saved
# user names database
users = db.users

# login manager
login_manager = flask_login.LoginManager()
login_manager.init_app(app)
##
#
class User(flask_login.UserMixin):
    pass

#forms that are used
class LoginForm(Form):
    username = StringField('username', validators=[DataRequired()])
    password = StringField('password', validators=[DataRequired()])
    email = StringField('email', validators=[DataRequired()])
    remember_me = BooleanField('remember_me', default=False)

class SearchForm(Form):
    search_term = StringField('name', validators=[DataRequired()])
    location = StringField('location', validators=[DataRequired()])

class RegisterForm(Form):
    username = StringField('username', validators=[DataRequired()])
    password = StringField('password', validators=[DataRequired()])
    email = StringField('email', validators=[DataRequired()])

# API constants, you shouldn't have to change these.
API_HOST = 'https://api.yelp.com'
SEARCH_PATH = '/v3/businesses/search'
BUSINESS_PATH = '/v3/businesses/'  # Business ID will come after slash.
TOKEN_PATH = '/oauth2/token'
GRANT_TYPE = 'client_credentials'
SEARCH_LIMIT = 5

CLIENT_ID = '8_f3OeYk3Xet1hRoUrq2qQ'#app.config['CLIENT_ID']
CLIENT_SECRET = 'IBcbN6KYSxCQp7GOwRKkdRJ1087wosdTbrjKHgif31voikQXzXNxwCxnYs1anCtt'#
#app.config['CLIENT_SECRET']

GOOGLEMAPS_KEY = "AIzaSyDPIxQ95g3W-PAd0WPy_PjM84-HtAKQp1U"

@login_manager.user_loader
def load_user(email):
    find_user = users.find_one({"email":email})
    if not find_user:
        return
    user = User()
    user.id = email

    return user

#
@app.route('/')
@app.route('/index')

def index():
    return render_template('homepage.html',
                            title='Home')

@app.route('/search', methods=['GET','POST'])
@flask_login.login_required
def search():
     form = SearchForm()
     # in the database
     uid = (flask_login.current_user.id)
     if form.validate_on_submit():

         search_term = form.search_term.data
         location = form.location.data
         x_results = saved_search.find_one({"search":search_term})
         if(x_results):
             print("already in the database")
             return render_template('results.html',
                            search_term = search_term,
                            results = x_results)
         else:
            print("not in the database yet")
            results = query_api(search_term, location)#query_api(search_term, location)
            new_post = {"search": search_term,
                            "rest1":results[1],
                            "rest2": results[2],
                            "rest3": results[3],
                            "rest4": results[4]}
            saved_search.insert(new_post)#.inserted_id
            ##zz = saved_search.find_one({"search": search_term})
            return render_template('index.html',
                            search_term = search_term,
                            results = results)

     return render_template('search.html',
                            title='Search',
                            form = form,)
@app.route('/logout')
@flask_login.login_required
def logout():
#    #uid = (flask_login.current_user.id)
    flask_login.logout_user()
    return render_template('index.html')
#
## index view function suppressed for brevity

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
         # see if its in the database

        find_user = users.find_one({"email":email})
        usename = users.find_one({"email":email}, {'username': 1})

        if(find_user):
            # now check if its the right password
            pwd = users.find_one({"email":email}, {'password': 1})

            if (password == pwd['password']):
                user = User()
                user.id = email
                print(flask_login.login_user(user))#, remember =True)
                flask_login.login_user(user)
                
                print("user already registed in the database" )
                #return redirect(url_for('mapview'))

                #return render_template('maptest.html', username = usename["username"])#, username = usename["username"])
                return redirect(url_for('mapview'))
            else:
                # if not the right password
                return 'Bad Login'

        else:
            print("user name not in the database yet")
            return "<a href='/login'>Try again</a>\
                    </br><a href='/register'>or make an account</a>"

    return render_template('login.html',
                           title='Sign In',
                           form=form)
#
def getuseridfromemail(email):
    uid = users.find_one({"email":'bob.test.com'}, {'username':1})
    return uid
    #cursor.execute("SELECT user_id  FROM Users WHERE email = '{0}'".format(email))
    #return cursor.fetchone()[0]

@login_manager.unauthorized_handler
def unauthorized_handler():
    return render_template('unauth.html')

@app.route("/register", methods=['GET','POST'])
def register_user():
    form = RegisterForm()
    username = form.username.data
    password = form.password.data
    email = form.email.data
    test =  isemailUnique(email)

    if test:
        new_post = {
            "username":username,
            "password":password,
            "email": email
        }
        user = User()
        user.id = email
        flask_login.login_user(user, remember = True)

        users.insert(new_post)
        uid = (flask_login.current_user.id)

        return render_template("maptest.html", username = username)
    else:
        print("couldn't find all tokens")
        return render_template('register.html',
                                title='Register',
                                form = form)

    return render_template('register.html',
                            title='Register',
                            form = form)

def isemailUnique(email):
    #use this to check if a email has already been registered
    find_user = users.find_one({"email":email})
    if find_user:
        #this means there are greater than zero entries with that email
        return False
    else:
        return True


#--------------------------------------
#yelp authentication
#--------------------------------------

def obtain_bearer_token(host, path):
    """Given a bearer token, send a GET request to the API.
    """
    url = '{0}{1}'.format(host, quote(path.encode('utf8')))
    #assert CLIENT_ID, "Please supply your client_id."
    #assert CLIENT_SECRET, "Please supply your client_secret."
    data = urlencode({
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': GRANT_TYPE,
    })
    headers = {
        'content-type': 'application/x-www-form-urlencoded',
    }
    response = request.request('POST', url, data=data, headers=headers)
    bearer_token = response.json()['access_token']
    return bearer_token

def request(host, path, bearer_token, url_params=None):

    url_params = url_params or {}
    url = '{0}{1}'.format(host, quote(path.encode('utf8')))
    headers = {
        'Authorization': 'Bearer %s' % bearer_token,
    }

    print(u'Querying {0} ...'.format(url))

    response = request.request('GET', url, headers=headers, params=url_params)

    return response.json()

def search(bearer_token, term, location):

    url_params = {
        'term': term.replace(' ', '+'),
        'location': location.replace(' ', '+'),
        'limit': SEARCH_LIMIT
    }
    return request(API_HOST, SEARCH_PATH, bearer_token, url_params=url_params)

def get_business(bearer_token, business_id):

    """Query the Business API by a business ID.
    Args:
        business_id (str): The ID of the business to query.
    Returns:
        dict: The JSON response from the request.
    """
    business_path = BUSINESS_PATH + business_id
    return request(API_HOST, business_path, bearer_token)

def query_api(term, location):

    bearer_token = obtain_bearer_token(API_HOST, TOKEN_PATH)
    response = search(bearer_token, term, location)
    businesses = response.get('businesses')

    if not businesses:
        x = (u'No businesses for {0} in {1} found.'.format(term, location))
        return x

    business_id = businesses[0]['id']
    array_ret = [None]*SEARCH_LIMIT

    for i in range(SEARCH_LIMIT):

        business_id = businesses[i]['id']
        business_name = businesses[i]['name']
        business_pic = businesses[i]['image_url']
        business_price = businesses[i]['price']
        business_rating = businesses[i]['rating']

        array_ret[i] = (business_id,business_name,business_pic,business_price,str(business_rating))

    print(u'{0} businesses found, querying business info ' \
        'for the top result "{1}" ...'.format(
            len(businesses), business_id))
    response = get_business(bearer_token, business_id)

    print(u'Result for business "{0}" found:'.format(business_id))
    #pprint.pprint(response, indent=2)
    return(array_ret)

#--------------------------------------
#facebook authentication
#--------------------------------------

from flask import url_for, request, session, redirect
from flask_oauth import OAuth

FACEBOOK_APP_ID = '426344891059039'
FACEBOOK_APP_SECRET = 'a9afa0f63af2cbc8385f7daaa9ca21dc'

oauth = OAuth()

facebook = oauth.remote_app('facebook',
    base_url='https://graph.facebook.com/',
    request_token_url=None,
    access_token_url='/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    consumer_key=FACEBOOK_APP_ID,
    consumer_secret=FACEBOOK_APP_SECRET,
    request_token_params={'scope': ('email, ')}
)

@facebook.tokengetter
def get_facebook_token():
    return session.get('facebook_token')

def pop_login_session():
    session.pop('logged_in', None)
    session.pop('facebook_token', None)
    
#https://www.facebook.com/dialog/oauth?scope=email%2C+&redirect_uri=http%3A%2F%2F0.0.0.0%3A5000%2Ffacebook_authorized&client_id=426344891059039

@app.route("/facebook_login")
def facebook_login():
    return facebook.authorize(callback=url_for('facebook_authorized',
        next=request.args.get('next'), _external=True))

@app.route("/facebook_authorized")
@facebook.authorized_handler
def facebook_authorized(resp):
    next_url = request.args.get('next') or url_for('mapview')
    if resp is None or 'access_token' not in resp:
        return redirect(next_url)

    session['logged_in'] = True
    session['facebook_token'] = (resp['access_token'], '')

    return redirect(next_url)
#
#@app.route("/fb_logout")
#def logout():
#    pop_login_session()
#    return redirect(url_for('homepage'))

##Querying information from facebook
def get_facebook_name():
	data = facebook.get('/me').data
	print data
	if 'id' in data and 'name' in data:
		user_id = data['id']
		user_name = data['name']
		return user_name

def get_facebook_friend_appuser():
	data = facebook.get('/me?fields=friends{first_name,last_name}').data
	print data
	return data

##--------------------------------------
##google maps authentication
##--------------------------------------
#
GoogleMaps(app)
##google map testing
@app.route("/mapview")
@flask_login.login_required
def mapview():
    uid = (flask_login.current_user.id)
    print("logged in as" +uid)
    return render_template('maptest.html', username = uid)
##
@app.route("/map_unsafe")
def map_unsafe():
    return render_template('maptest.html')

if __name__ == '__main__':

    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
