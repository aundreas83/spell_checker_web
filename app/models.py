from datetime import datetime
from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app import login


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uname = db.Column(db.String(64), index=True, unique=True)
    twofa = db.Column(db.String(64), index=True, unique=True)
    pword = db.Column(db.String(128))

    def set_password(self, pword):
        self.password_hash = generate_password_hash(pword)

    def check_password(self, pword):
        return check_password_hash(self.password_hash, pword)

    def __repr__(self):
        return '<User {}>'.format(self.uname)

@login.user_loader
def load_user(id):
    return User.query.get(int(id))


