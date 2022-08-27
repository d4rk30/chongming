from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask('chongming')
app.config.from_pyfile('setting.py')

db = SQLAlchemy(app)

from chongming import views, commond, task
