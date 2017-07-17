import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_login import login_user, logout_user, current_user, login_required
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = '123456789'
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:1234@localhost/flask"
app.config['DEBUG'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(minutes=30)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
