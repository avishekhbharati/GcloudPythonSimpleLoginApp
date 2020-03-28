import os
import urllib

from google.appengine.ext import ndb
from gaesessions import get_current_session

import jinja2
import webapp2

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)
# [END imports]


def user_key(id):
    return ndb.Key('User', id)


class User(ndb.Model):
    id = ndb.KeyProperty(indexed=True, kind='User')
    name = ndb.StringProperty(indexed=False)
    password = ndb.IntegerProperty(indexed=False)
# [END User]


class LoginHandler(webapp2.RequestHandler):

    def get(self):        
        template = JINJA_ENVIRONMENT.get_template('login.html')
        self.response.write(template.render())

    def post(self): 
        userid = self.request.get('userid').strip()
        password = self.request.get('password').strip()

        #template value for invalid inputs
        template_values_invalid_unpwd = {
                'message' : 'User id or password is invalid.',
            }

        if userid == '' or password == '':            
            template = JINJA_ENVIRONMENT.get_template('login.html')
            self.response.write(template.render(template_values_invalid_unpwd))
        else:
            users = User.query().filter(User.id == user_key(userid)).fetch(1)

            if len(users) != 0 and isInteger(password) and  users[0].password == int(password):
                session = get_current_session()
                session['user'] = users[0]
                session['userid'] = users[0].id
                session['username'] = users[0].name
                session['password'] = users[0].password

                self.redirect('/main')
            else:
                template = JINJA_ENVIRONMENT.get_template('login.html')
                self.response.write(template.render(template_values_invalid_unpwd))
# [END login]


class MainPageHandler(webapp2.RequestHandler):
    def get(self):
        session = get_current_session()
        if session.is_active():
            template_values = {
                'username' : session['username'],
                'userid' : session['userid']
            }
            template = JINJA_ENVIRONMENT.get_template('main.html')
            self.response.write(template.render(template_values))
        else:
            self.redirect('/')
# [END Main]


class NameHandler(webapp2.RequestHandler):
    def get(self): 
        session = get_current_session()
        if session.is_active():
            template = JINJA_ENVIRONMENT.get_template('name.html')
            self.response.write(template.render())
        else:
            self.redirect('/')

    def post(self):
        session = get_current_session()
        if session.is_active():
            username = self.request.get('username').strip()
            if username == '':
                template_values = {
                    'message':'User name cannot be empty'
                }
                template = JINJA_ENVIRONMENT.get_template('name.html')
                self.response.write(template.render(template_values))
            else:
                #update the entity in datastore
                user = session['user']
                user.name = username
                user.put()

                session['user'] = user
                session['username'] = user.name
                self.redirect('/main')
        else:            
            self.redirect('/')

# [END Main]


class PasswordHandler(webapp2.RequestHandler):

    def get(self): 
        session = get_current_session()
        if session.is_active():
            template = JINJA_ENVIRONMENT.get_template('password.html')
            self.response.write(template.render())
        else:
            self.redirect('/')
    
    def post(self):
        session = get_current_session()

        oldpassword = self.request.get('oldpassword').strip()
        newpassword = self.request.get('newpassword').strip()  

        if oldpassword == '' or newpassword == '':
            template_values = {
                'message': 'Fields cannot be empty.'
            }
            template = JINJA_ENVIRONMENT.get_template('password.html')
            self.response.write(template.render(template_values))
        elif oldpassword != str(session['password']):
            template_values = {
                'message': 'User password is incorrect'
            }
            template = JINJA_ENVIRONMENT.get_template('password.html')
            self.response.write(template.render(template_values))
        else:
            if isInteger(newpassword):                
                user = session['user']
                user.password = int(newpassword)
                user.put()
                self.redirect('/logout')
            else:
                template_values = {
                    'message': 'Please enter numbers for password.'
                }
                template = JINJA_ENVIRONMENT.get_template('password.html')
                self.response.write(template.render(template_values))
# [END PassswordHandler]

#verifies if the given value is string
def isInteger(x):
    try:
        y = int(x)
        return True
    except:
        return False
    return False


class LogOutHandler(webapp2.RequestHandler):
    def get(self):
        session = get_current_session()
        session.terminate()
        self.redirect('/')


# [START app]
app = webapp2.WSGIApplication([
    ('/', LoginHandler),
    ('/main', MainPageHandler),
    ('/name', NameHandler),
    ('/password', PasswordHandler),
    ('/logout', LogOutHandler)
], debug = True)
# [END app]