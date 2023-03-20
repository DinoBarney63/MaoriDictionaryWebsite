from flask import Flask, render_template, redirect, request, session
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt

DATABASE = "C:/Users/19164/PycharmProjects/Pycharm---MaoriDictionaryWebsite/MaoriDictionary.db"  # School Computer
# DATABASE = "C:/Users/ryanj/PycharmProjects/Pycharm---MaoriDictionaryWebsite/MaoriDictionary.db"  # Home Laptop

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "Key123"  # Whatever you want


def create_connection(db_file):
    """
    Create a connection with the database
    parameter: name of the database file
    return: a connection to the file
    """
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(e)
    return None


def is_logged_in():
    if session.get('email') is None:
        return False
    else:
        return True


@app.route('/')
def render_home():
    return render_template('home.html', logged_in=is_logged_in())


@app.route('/wordlist')
def render_wordlist():
    return render_template('wordlist.html', logged_in=is_logged_in())


@app.route('/login', methods=['POST', 'GET'])
def render_login():
    if is_logged_in():
        return redirect('/menu/0')
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()
        con = create_connection(DATABASE)
        query = """SELECT id, first_name, password FROM user WHERE email = ?"""
        cur = con.cursor()
        cur.execute(query, (email,))
        user_data = cur.fetchone()
        con.close()
        # if given the email that is not in the database this will raise an error
        # would be better to find out how to see if the query return an empty result set
        try:
            user_id = user_data[0]
            first_name = user_data[1]
            db_password = user_data[2]
        except IndexError:
            return redirect("/login?error=Email+invalid+or+password+incorrect")

        if not bcrypt.check_password_hash(db_password, password):
            return redirect(request.referrer + "error=Email+invalid+or+password+incorrect")

        session['email'] = email
        session['userid'] = user_id
        session['firstname'] = first_name

        return redirect('/')

    return render_template('login.html', logged_in=is_logged_in())


@app.route('/logout')
def logout():
    [session.pop(key) for key in list(session.keys())]
    return redirect('/?message=See+you+next+time!')


@app.route('/signup', methods=['POST', 'GET'])
def render_signup():
    if is_logged_in():
        return redirect('/menu/0')
    if request.method == 'POST':
        first_name = request.form.get('first_name').title().strip()
        last_name = request.form.get('last_name').title().strip()
        email = request.form.get('email').lower().strip()
        password = request.form.get('password')
        password2 = request.form.get('password2')

        if password != password2:
            return redirect("\signup?error=Passwords+do+not+match")

        if len(password) < 8:
            return redirect("\signup?error=Passwords+must+be+at+least+8+characters")

        hashed_password = bcrypt.generate_password_hash(password)
        con = create_connection(DATABASE)
        query = "INSERT INTO user (first_name, last_name, email, password, is_admin) VALUES (?, ?, ?, ?, ?)"
        cur = con.cursor()

        try:
            cur.execute(query, (first_name, last_name, email, hashed_password, "0"))
        except sqlite3.IntegrityError:
            con.close()
            return redirect('\signup?error=Email+is+already+used')

        con.commit()
        con.close()

        return redirect("login")

    return render_template('signup.html', logged_in=is_logged_in())


app.run()  # Runs app normally
# app.run(host='0.0.0.0', debug=True)  # Lets other invade your website
