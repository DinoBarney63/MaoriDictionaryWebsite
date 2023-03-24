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


def is_admin():
    if is_logged_in():
        if session.get('role') == "Teacher" or session.get('role') == "Admin":
            return True
        else:
            return False
    else:
        return False


@app.route('/')
def render_home():
    return render_template('home.html', logged_in=is_logged_in(), admin=is_admin())


@app.route('/wordlist')
def render_wordlist():
    con = create_connection(DATABASE)
    query = "SELECT id, maori_word, english_word, category, level FROM vocab_list"
    cur = con.cursor()
    cur.execute(query, )
    word_list = cur.fetchall()
    con.close()
    return render_template('wordlist.html', logged_in=is_logged_in(), admin=is_admin(), word_list=word_list)


@app.route('/individualword/<word_id>')
def render_individual_word(word_id):
    con = create_connection(DATABASE)
    query = "SELECT * FROM vocab_list WHERE word_id = ?"
    cur = con.cursor()
    cur.execute(query, (word_id, ))
    word_info = cur.fetchall()
    con.close()
    return render_template('wordlist.html', logged_in=is_logged_in(), admin=is_admin(), word_infomation=word_info)


@app.route('/login', methods=['POST', 'GET'])
def render_login():
    if is_logged_in():
        return redirect('/')
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()
        con = create_connection(DATABASE)
        query = """SELECT id, first_name, password, role FROM user WHERE email = ?"""
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
            role = user_data[3]
        except IndexError:
            return redirect("/login?error=Email+invalid+or+password+incorrect")

        if not bcrypt.check_password_hash(db_password, password):
            return redirect(request.referrer + "error=Email+invalid+or+password+incorrect")

        session['email'] = email
        session['userid'] = user_id
        session['firstname'] = first_name
        session['role'] = role

        email_parts = email.split('.')
        if "school" in email_parts:
            if role == "User":
                redirect('render_confirm_school_role')

        return redirect('/')

    return render_template('login.html', logged_in=is_logged_in(), admin=is_admin())


@app.route('/logout')
def logout():
    [session.pop(key) for key in list(session.keys())]
    return redirect('/?message=See+you+next+time!')


@app.route('/signup', methods=['POST', 'GET'])
def render_signup():
    if is_logged_in():
        return redirect('/')
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
        query = "INSERT INTO user (first_name, last_name, email, password, role) VALUES (?, ?, ?, ?, ?)"
        cur = con.cursor()

        try:
            cur.execute(query, (first_name, last_name, email, hashed_password, "User"))
        except sqlite3.IntegrityError:
            con.close()
            return redirect('\signup?error=Email+is+already+used')

        con.commit()
        con.close()

        return redirect('login')

    return render_template('signup.html', logged_in=is_logged_in(), admin=is_admin())


# Try make it activate this after signing up as well as after logging in
@app.route('/confirm_school_role/<user_id>')
def render_confirm_school_role(user_id):
    con = create_connection(DATABASE)
    query = "SELECT email, role FROM user WHERE id = ?"
    cur = con.cursor()
    cur.execute(query, (user_id, ))
    user_info = cur.fetchall()
    con.close()
    email = user_info[0]
    role = user_info[0]
    email_parts = email.split('.')
    if "school" in email_parts:
        if role == "User":
            return render_template('confirmschoolrole.html', user_id=user_id)
    else:
        return redirect('/')


@app.route('/signup_student/<user_id>')
def signup_student(user_id):
    con = create_connection(DATABASE)
    query = "UPDATE user SET role='Student' WHERE id = ?"
    cur = con.cursor()
    cur.execute(query, (user_id,))
    con.commit()
    con.close()
    return redirect('/')


@app.route('/signup_teacher/<user_id>')
def signup_teacher(user_id):
    con = create_connection(DATABASE)
    query = "UPDATE user SET role='Teacher' WHERE id = ?"
    cur = con.cursor()
    cur.execute(query, (user_id,))
    con.commit()
    con.close()
    return redirect('/')


app.run()  # Runs app normally
# app.run(host='0.0.0.0', debug=True)  # Lets other invade your website
