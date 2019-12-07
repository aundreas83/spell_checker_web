from flask import render_template, Flask, redirect, url_for, flash, request, Markup
from app import app, db, models
from app.forms import LoginForm, RegistrationForm, Spell_Checker
from flask_login import LoginManager, current_user, login_user, login_required, logout_user
from app.models import User
import subprocess
import os

basedir = os.path.abspath(os.path.dirname(__file__))
login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.session_protection = "strong"

@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(user_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        user_2fa = User.query.filter_by(twofactorauth=form.twofactorauth.data).first()
        if user is None or not user.check_password(form.password.data) or user_2fa is None:
            flash(Markup('<li id="result">Invalid username, password or 2FA verification</li>'))
            return redirect(url_for('login'))
        user.authenticated = True
        login_user(user, remember=form.remember_me.data)
        flash(Markup('Logged in successfully. <li id="result"> success </li>'))
        return redirect(url_for('spell_checker'))
    return render_template('login.html', title='Sign In', form=form)

@app.route('/spell_check', methods=['GET', 'POST'])
def spell_checker():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    form = Spell_Checker()
    if form.validate_on_submit():
        f = open("check.txt", "w")
        f.write(form.spellchecker.data)
        f.close()

        proc2 = subprocess.Popen(basedir + '/a.out check.txt wordlist.txt', stdin=None, shell=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        proc3 = proc2.stdout
        output = None
        for words in proc3:
            words = words.decode("utf-8").split()
            for word in words:
                if output is None:
                    output = word
                else:
                    output = output + ", " + word

        if output is None:
            output = "There are no misspelled words"

        flash(Markup('<li id=textout>The incorrect words are:  </li><li id="misspelled">' + output + ' </li>'))
    return render_template('spell_check.html', title="Spell Checker", form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@app.route('/index')
@login_required
def index():
    return render_template("index.html", title='Home Page')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        flash('Already registered!')
        return redirect(url_for('index'))
    form = RegistrationForm()
    if request.method == 'POST' and form.validate_on_submit():
        user = models.User(username=form.username.data, twofactorauth=form.twofactorauth.data, password=form.password.data)
        user.authenticated = True
        db.session.add(user)
        db.session.commit()
        flash(Markup('Registered successfully. <li id="result"> success </li>'))
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)
