from flask_bcrypt import Bcrypt
from flask import Flask, render_template, redirect, session, flash, request
from flask_app import app
from flask_app.config.mysqlconnection import MySQLConnection
from flask_app.models import user

# main page with user/new user login and reg
@app.route('/user_login')
def user_login():
    return render_template('dash.html')

# page for when user signs in/user display page
@app.route('/user_welcome')
def user_welcome():
    data = {
        'id': session['user_id']
    }
    if 'user_id' not in session:
        return redirect("/user_login")
    user_session = user.User.select_id(data)
    return render_template('welcome.html', user_session = user_session)

# action to register new user
@app.route('/register', methods=['POST'])
def user_reg():
    if not user.User.validate_user(request.form):
        return redirect('/user_login')
    else:
        user.User.new_user(request.form)

    data = {
        "first_name": request.form['first_name'],
        "last_name": request.form['last_name'],
        "email": request.form['email'],
        "password": Bcrypt.generate_password_hash(request.form['password'])
    }
    session ['user_id'] = user.User.new_user(data)
    return redirect('/user_welcome')

# action for user login
@app.route('/login', methods=['POST'])
def login():
    data = {
        'email': request.form['email']
    }
    user_sessions = user.User.select_email(data)

    if not user.User.validate_email(request.form):
        session['email'] = request.form['email']
        session['id'] = user_sessions.id
        return redirect('/user_login')
    else:
        session ['user_id'] = user_sessions.id
        return redirect('/user_welcome')

# logout action to clear session
@app.route('/logout')
def logout():
    session.clear()
    return redirect ('/user_login')
