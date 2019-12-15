from flask import render_template, Flask, redirect, url_for, flash, request, Markup, abort
from app import app, db, models
from app.forms import LoginForm, RegistrationForm, Spell_Checker, SearchUsersForm
from flask_login import LoginManager, current_user, login_user, login_required, logout_user
from app.models import User, SpellCheckHistory, UserHistory
import flask
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
            flash(Markup('Invalid username, password or 2FA verification <li class="danny" id="result">failed</li>'))
            return redirect(url_for('login'))
        user.authenticated = True
        login_user(user, remember=form.remember_me.data)
        flash(Markup('Logged in successfully. <li class="danny" id="result"> success </li>'))

        log_login = UserHistory(action="login", user=current_user)
        db.session.add(log_login)
        db.session.commit()
        return redirect(url_for('spell_checker'))
    return render_template('login.html', title='Sign In', user_search=str(current_user), form=form)

@app.route('/spell_check', methods=['GET', 'POST'])
@login_required
def spell_checker():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    form = Spell_Checker()
    if flask.request.method == "POST":
        if form.validate_on_submit():
            f = open("check.txt", "w")
            f.write(form.spellchecker.data)
            f.close()

            proc2 = subprocess.Popen(basedir + '/a.out check.txt wordlist.txt', stdin=None,
                    shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
            save_SpellCheckHistory = SpellCheckHistory(query_spelling=form.spellchecker.data, store_spell_results=output, user=current_user)
            db.session.add(save_SpellCheckHistory)
            db.session.commit()

        return render_template("spell_check.html", title="Spell Checker", user_search=str(current_user), form=form)
    if request.method == "GET":
        saved_SpellCheckHistory = SpellCheckHistory.query.filter_by(user_id=current_user.id).first()
        retrieved_data = getattr(saved_SpellCheckHistory, "query_spelling", None)

        login_success = request.args.get("login_success")
        return render_template("spell_check.html", title="Spell Check", user_search=str(current_user), form=form, input_data=retrieved_data, login_success=True,)

@app.route('/logout')
@login_required
def logout():
    user=current_user
    log_logout = UserHistory(action="logout", user=user)
    db.session.add(log_logout)
    db.session.commit()
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@app.route('/index')
def index():
    return render_template("index.html", title='Home Page', user_search=str(current_user), )

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
        flash(Markup('Registered successfully. <li id="success"> success </li>'))
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', user_search=str(current_user), form=form)


@app.route("/history", methods=["GET", "POST"])
@app.route("/history/query<query_id>")
@login_required
def history(query_id=None):
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    form = SearchUsersForm()
    if request.method == "GET":
        spellcheck_query = SpellCheckHistory.query.filter_by(user_id=current_user.id).all()
        count = len(spellcheck_query)

        if query_id is not None:
            query = SpellCheckHistory.query.filter_by(id=query_id).first()
            if not query.permission_allowed(current_user):
                abort(403)
        else:
            query = None

        return render_template("history.html", queries=spellcheck_query, count=count,
            query_id=query_id,
            user_search=current_user,
            user=current_user,
            query=query,
            form=form,)

    if request.method == "POST":
        if str(current_user) != "admin":
            abort(403)

        if form.validate_on_submit():
            user_search = User.query.filter_by(username=form.username.data).first()
            user_history = SpellCheckHistory.query.filter_by(user_id=user_search.id)

            return render_template(
                "history.html",
                queries=user_history,
                count=len(user_history.all()),
                user_search=user_search,
                query_id=query_id,
                user=current_user,
                query=user_history,
                form=form,)

@app.route("/login_history", methods=["GET", "POST"])
@login_required
def login_history():
    if str(current_user) != "admin":
        abort(403)

    form = SearchUsersForm()
    if request.method == "GET":
        return render_template("login_history.html", user_search=current_user, user=current_user, form=form,)

    if request.method == "POST":
        if form.validate_on_submit():
            user_search = User.query.filter_by(username=form.username.data).first()
            user_search_history = UserHistory.query.filter_by(user_id=user_search.id).all()
        return render_template("login_history.html", user_search=current_user, user=current_user, queries=user_search_history, form=form,)
