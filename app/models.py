import datetime
from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app import login
from app import db

db.create_all()

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

class User(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    twofactorauth = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(128))

    def __init__(self, username, password, twofactorauth):
        self.username = username
        self.password_hash = generate_password_hash(password)
        self.twofactorauth = twofactorauth
        self.authenticated = False


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def userid(self):
        return self.username

    def __repr__(self):
        return '{}'.format(self.username)

class SpellCheckHistory(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    query_spelling = db.Column(db.Text())
    store_spell_results = db.Column(db.Text())
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user = db.relationship("User")

    def permission_allowed(self, user):
        if self.user == user or str(user) == "admin":
            return True
        return False

class UserHistory(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(80))
    action_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user = db.relationship("User")
