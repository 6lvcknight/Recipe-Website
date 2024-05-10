from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user


auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password1')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        firstName = request.form.get('fName')
        lastName = request.form.get('lName')
        email = request.form.get('email')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(firstName) < 2:
            flash("First name is too short.", category='error')
        elif len(lastName) <  2:
            flash("Last name is too short.", category='error')
        elif password1 != password2:
            flash("Passwords do not match.", category='error')
        elif len(email) < 4:
            flash('Email is too short.', category='error')   
        else:
            new_user = User(email=email, first_name=firstName, last_name=lastName, 
                            password=generate_password_hash(password1, method='pbkdf2:sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash("Account created.", category='success')
            return redirect(url_for('views.home'))

    return render_template("signup.html", user=current_user)

@auth.route('/forgotpassword', methods=['GET', 'POST'])
def fpassword():
    if request.method == 'POST':
        email = request.form.get('email')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Email does not exist.", category='error')
            return render_template("signup.html", user=current_user)
        if password1 != password2:
            flash("Passwords do not match.", category='error')
        else:
            user.password = generate_password_hash(password1, method='pbkdf2:sha256')
            db.session.commit()
            flash("Password has been updated.", category='success')
            return render_template("login.html", user=current_user)


    return render_template("forgot_password.html", user=current_user)