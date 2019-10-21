from flask import render_template, Flask, redirect, url_for, flash, request, Markup
from app import app, db
from app.forms import LoginForm, RegistrationForm
from flask_login import current_user, login_user, login_required, logout_user
from app.models import User
from werkzeug.urls import url_parse

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.uname.data).first()
        user_2fa = User.query.filter_by(twofactorauth=form.twofactorauth.data).first()
        if user is None or not user.check_password(form.pword.data):
            flash(Markup('<li id="result">Invalid username or password</li>'))
            if user_2fa is None:
                flash(Markup('<li id="result">Two-factor failure</li>'))
                return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        flash(Markup('Logged in successfully. <li id="result"> success </li>'))
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)

@app.route('/spell_check')
def spell_checker():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    form = Spell_Checker()
    return render_template('spell_check.html', title="Spell Checker", form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/')
@app.route('/index')
@login_required
def index():
    return render_template("index.html", title='Home Page')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.uname.data, twofactorauth=form.twofactorauth.data)
        user.set_password(form.pword.data)
        db.session.add(user)
        db.session.commit()
        flash(Markup('<li id="success">success</li>'))
    return render_template('register.html', title='Register', form=form)
