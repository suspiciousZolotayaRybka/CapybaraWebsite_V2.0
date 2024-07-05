"""
SDEV 300 6384
Author: Isaac Finehout
Date: 5 October 2023
Lab 8: Security and Cipher Tools
"""
import datetime
import string

from functools import wraps
from ast import literal_eval
from flask import Flask, request, flash, redirect, url_for, session
from flask import render_template
from passlib.hash import sha256_crypt
# test
print("test")

app = Flask(__name__)
app.secret_key = '7!oZOpHiF*7j5=AyI@4u'


def log_information(ip_address, information):
    """
    Logs information into the capybara_log.txt file
    :param ip_address: the user's IP address
    :param information: the information to be logged
    :return: returns nothing
    """
    with open('static/capybara_log.txt', "a", encoding="UTF-8") as file:
        file.write(str(datetime.datetime.now()) + ": " +
                   information + " IP:" + str(ip_address) + "\n")


def valid_login(username, password):
    """
    Check that the user entered a username and password
    Check that the user's password is correct
    :param username:
    :param password:
    :return:
    """
    user_dict: dict
    hash_index: int = 0
    capy_name_index: int = 1
    with open('static/super_secure_user_database/passfile.txt', "r", encoding="UTF-8") as file:
        file_content = file.read()
        if file_content == "":
            user_dict = {}
        else:
            user_dict = literal_eval(file_content)
    if not username:
        error = "No username"
        flash(error)
        return False, None, error
    if not password:
        error = "No password"
        flash(error)
        return False, None, error
    if username not in user_dict:
        error = "User does not exist"
        flash(error)
        return False, None, error
    if not sha256_crypt.verify(password, user_dict[username][hash_index]):
        error = "Passwords do not match"
        flash(error)
        return False, None, error
    return True, user_dict[username][capy_name_index], None


@app.route('/CapybaraLogin/', methods=['GET', 'POST'])
def capybara_login():
    """
    Authenticate the user
    Prompt the user to log in with their capybara credentials
    :return: render capybara login
    """
    error = None
    if request.method == 'POST':
        is_login_valid, capy_name, error = valid_login(request.form['username'],
                                                       request.form['password'])
        if is_login_valid:
            session['username'] = request.form['username']
            log_information(request.environ.get('HTTP_X_REAL_IP', request.remote_addr),
                            "Login/" + "UserLoggedIn/" + request.form['username'])
            return redirect(url_for("capybara_homepage", capy_name=capy_name))
        # Login was not valid, return an error
        log_information(request.environ.get('HTTP_X_REAL_IP',
                                            request.remote_addr), "Error/Login/" + error)
        # Minimize amount of error information shown to potential attackers
        error = 'Invalid username/password'
    return render_template("CapybaraLogin.html",
                           current_date=str(datetime.datetime.now())[:19], error=error)


def valid_password(password, confirm_password):
    """
    Takes a password to ensure it meets password length and complexity requirements
    :param password: the password the user enters
    :param confirm_password: the second password the user enters to confirm their password
    :return:
    """
    error = None
    common_passwords: str = ""
    # This file will compare their password against a list of commonly used passwords
    with open('static/CommonPassword.txt', "r", encoding="UTF-8") as file:
        for line in file:
            # Concatenate each line without the line breaks to the common_passwords string
            # Using a string instead of a list also catches shorter passwords
            common_passwords += line[:len(line) - 1]
    if password in common_passwords:
        error = "The attempted password is in a list of the most common passwords"
    elif password != confirm_password:
        error = "Passwords must match"
    elif len(password) <= 12:
        error = "Password must be at least 12 characters in length"
    elif not any(c.islower() for c in password):
        error = "Password must include at least 1 lowercase character"
    elif not any(c.isupper() for c in password):
        error = "Password must include at least 1 uppercase character"
    elif not any(c.isdigit() for c in password):
        error = "Password must include at least 1 digit"
    elif not any(c in string.punctuation for c in password):
        error = "Password must include at least 1 special character"
    return error


def valid_register(username, password, confirm_password, capy_name):
    """
    Check for valid credentials and a valid account
    :param username: username
    :param password: password
    :param confirm_password: confirm_password
    :param capy_name: capy_name
    :return: return the error
    """
    user_dict: dict
    # Validate user input
    # This file will check if the user is already enrolled
    with open('static/super_secure_user_database/passfile.txt', "r", encoding="UTF-8") as file:
        file_content = file.read()
        if file_content == "":
            user_dict = {}
        else:
            user_dict = literal_eval(file_content)
    if username in user_dict:
        error = "User is already registered"
    elif not username or not password or not confirm_password or not capy_name:
        error = "All inputs require data"
    else:
        error = valid_password(password, confirm_password)
    return error


def encrypt_and_store_credentials(username, password, capy_name):
    """
    Hash the user's information and store it inside a file
    :param username: username
    :param password: password
    :param capy_name: capy_name
    :return:
    """
    user_dict: dict
    with open('static/super_secure_user_database/passfile.txt', "r", encoding="UTF-8") as file:
        file_content = file.read()
        if file_content == "":
            user_dict = {}
        else:
            user_dict = literal_eval(file_content)
    with open('static/super_secure_user_database/passfile.txt', 'w', encoding="UTF-8") as file:
        user_dict[username] = [sha256_crypt.hash(password), capy_name]
        file.write(str(user_dict))


@app.route('/CapybaraRegister/', methods=['GET', 'POST'])
def capybara_register():
    """
    Prompt the user to register with their capybara credentials
    :return: render capybara register
    """
    # Assign user variables
    if request.method == 'POST':
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm-password"]
        capy_name = request.form["capy-name-select"]
        error = valid_register(username, password, confirm_password, capy_name)
        flash(error)
        # If there is no error, redirect the user to the capybara homepage and store credentials
        if error is None:
            encrypt_and_store_credentials(username, password, capy_name)
            log_information(request.environ.get('HTTP_X_REAL_IP', request.remote_addr),
                            "Registration/" + "NewUser/" + username)
            return redirect(url_for("capybara_login"))
        # Log the error and redirect the user if an error exists
        log_information(request.environ.get('HTTP_X_REAL_IP',
                                            request.remote_addr), "Error/Registration/" + error)
        return render_template("CapybaraRegister.html",
                               current_date=str(datetime.datetime.now())[:19], error=error)
    return render_template("CapybaraRegister.html",
                           current_date=str(datetime.datetime.now())[:19])


def login_required(restricted_function):
    """
    Used as a wrapper to prevent unauthenticated users from accessing pages
    :param restricted_function: the route unauthenticated users are prevented from using
    :return: decorated_function
    """
    @wraps(restricted_function)
    def decorated_function(*args, **kwargs):
        """
        Check to see if the current session has a user, and allow them in if so
        :param args: arguments for the route the user is trying to access
        :param kwargs: keyword arguments for the route the user is trying to access
        :return: return the restricted route or the login page based on user authentication status
        """
        if 'username' not in session:
            flash('You need to login first.')
            log_information(request.environ.get('HTTP_X_REAL_IP', request.remote_addr),
                            "Error/UnauthorizedAccessAttempt/" + str(restricted_function))
            return redirect(url_for("capybara_login"))
        return restricted_function(*args, **kwargs)
    return decorated_function


@app.route('/CapybaraHomepage/<capy_name>')
@login_required
def capybara_homepage(capy_name):
    """
    Show the user the main Capybara HTML homepage
    :return: render capybara homepage
    """
    return render_template("CapybaraHomepage.html",
                           current_date=str(datetime.datetime.now())[:19], capy_name=capy_name)


@app.route('/CapybaraHomepage/CapybaraNature/<capy_name>')
@login_required
def capybara_nature(capy_name):
    """
    Show the user the Capybara Nature HTML page
    :return: render capybara nature
    """
    return render_template("CapybaraNature.html",
                           current_date=str(datetime.datetime.now())[:19], capy_name=capy_name)


@app.route('/CapybaraHomepage/CapybaraPopculture/<capy_name>')
@login_required
def capybara_popculture(capy_name):
    """
    Show the user the Capybara Popculture HTML page
    :return: render capybara popculture
    """
    return render_template("CapybaraPopculture.html",
                           current_date=str(datetime.datetime.now())[:19], capy_name=capy_name)


@app.route('/CapybaraHomepage/CapybaraAction/<capy_name>')
@login_required
def capybara_action(capy_name):
    """
    Show the user the Capybara Action HTML page
    :return: render capybara action
    """
    return render_template("CapybaraAction.html",
                           current_date=str(datetime.datetime.now())[:19], capy_name=capy_name)


def valid_password_change(current_password, new_password, confirm_password):
    """
    :param current_password: user's old password
    :param new_password: the new password
    :param confirm_password:
    :return: return the error
    """
    user_dict: dict
    hash_index: int = 0
    with open('static/super_secure_user_database/passfile.txt', "r", encoding="UTF-8") as file:
        file_content = file.read()
        if file_content == "":
            user_dict = {}
        else:
            user_dict = literal_eval(file_content)
    if not sha256_crypt.verify(current_password, user_dict[session['username']][hash_index]):
        error = "Incorrect current password"
    elif current_password == new_password:
        error = "New password cannot be the same as old password"
    else:
        error = valid_password(new_password, confirm_password)
    return error


@app.route('/CapybaraHomepage/ChangePassword/<capy_name>', methods=['GET', 'POST'])
@login_required
def change_password(capy_name):
    """
    Routes the user to change their password
    :return: render change password
    """
    if request.method == 'POST':
        current_password = request.form["current-password"]
        new_password = request.form["new-password"]
        confirm_password = request.form["confirm-password"]
        error = valid_password_change(current_password, new_password, confirm_password)
        flash(error)
        # If there is no error, redirect the user to the capybara login to test their new password
        if error is None:
            encrypt_and_store_credentials(session['username'], new_password, capy_name)
            log_information(request.environ.get('HTTP_X_REAL_IP', request.remote_addr),
                            "ChangePassword/" + session['username'])
            return redirect(url_for('logout'))
        # If there is an error, inform the user and log it
        log_information(request.environ.get('HTTP_X_REAL_IP',
                                            request.remote_addr), "Error/ChangePassword/" + error)
        return render_template("ChangePassword.html",
                               current_date=str(datetime.datetime.now())[:19],
                               capy_name=capy_name, error=error)
    return render_template("ChangePassword.html",
                           current_date=str(datetime.datetime.now())[:19], capy_name=capy_name)


@app.route('/logout/')
def logout():
    """
    Function routed the user to log out, remove their session
    :return: route user to log in page
    """
    log_information(request.environ.get('HTTP_X_REAL_IP', request.remote_addr),
                    "Login/" + "UserLoggedOut/" + session['username'])
    session.pop('username', None)
    return redirect(url_for('capybara_login'))


if __name__ == '__main__':
    app.run()
