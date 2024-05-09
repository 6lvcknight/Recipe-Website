from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db


auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    return render_template("login.html")

@auth.route('/logout')
def logout():
    return '<p>its incomplete</p>'

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        firstName = request.form.get('fName')
        lastName = request.form.get('lName')
        email = request.form.get('email')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        if len(email) < 4:
            flash('Email is too short.', category='error')
        elif len(firstName) < 2:
            flash("First name is too short.", category='error')
        elif len(lastName) <  2:
            flash("Last name is too short.", category='error')
        elif password1 != password2:
            flash("Passwords do not match.", category='error')
        else:
            new_user = User(email=email, first_name=firstName, last_name=lastName, 
                            password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash("Account created.", category='success')
            return redirect(url_for('views.home'))

    return render_template("signup.html")