from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from app.models import User

class LoginForm(FlaskForm):
    uname = StringField('Username', validators=[DataRequired()])
    pword = PasswordField('Password', validators=[DataRequired()])
    twofactorauth = StringField('2FA', id='2fa', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    uname = StringField('Username', validators=[DataRequired()])
    twofactorauth = StringField('2FA', id='2fa', validators=[DataRequired()])
    pword = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_username(self, uname):
        user = User.query.filter_by(uname=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

class Spell_Checker(FlaskForm):
    spellchecker = StringField('Check words', validators=[DataRequired()])
    submit = SubmitField('Submit')

