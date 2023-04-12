from flask import Flask, render_template, redirect, request, session
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt

# DATABASE = "C:/Users/19164/PycharmProjects/Pycharm---MaoriDictionaryWebsite/MaoriDictionary.db"  # School Computer
DATABASE = "C:/Users/ryanj/PycharmProjects/Pycharm---MaoriDictionaryWebsite/MaoriDictionary.db"  # Home Laptop

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


def in_school():
    if is_logged_in():
        email_parts = session.get('email').split('.')
        if "school" in email_parts:
            return True
    else:
        return False


@app.route('/')
def render_home():
    if in_school():
        if session['role'] == 'User':
            return redirect('/confirm_school_role/' + str(session['userid']))

    return render_template('home.html', page_name='Home', logged_in=is_logged_in(), admin=is_admin())


@app.route('/word_list/<category_id>')
def render_word_list(category_id):
    con = create_connection(DATABASE)
    query = "SELECT id, name FROM category"
    cur = con.cursor()
    cur.execute(query)
    category_list = cur.fetchall()
    
    if category_id == "0":
        query = "SELECT id, maori_word, english_translation, category, level FROM vocab_list"
        cur = con.cursor()
        cur.execute(query)
    else:
        category = category_list[int(category_id) - 1][1]
        query = "SELECT id, maori_word, english_translation, category, level FROM vocab_list WHERE category=?"
        cur = con.cursor()
        cur.execute(query, (category, ))
    words = cur.fetchall()
    con.close()
    word_list = []
    # Reformatting the words to be displayed
    for word in words:
        word = (word[0], str(word[1]).title(), str(word[2]).title(), str(word[3]).title(), word[4])
        word_list.append(word)
    return render_template('word_list.html', page_name='Words', logged_in=is_logged_in(), admin=is_admin(), word_list=word_list, category_list=category_list)


@app.route('/individual_word/<word_id>')
def render_individual_word(word_id):
    con = create_connection(DATABASE)
    query = "SELECT * FROM vocab_list WHERE id = ?"
    cur = con.cursor()
    cur.execute(query, (word_id, ))
    info = cur.fetchall()
    con.close()
    info = info[0]
    word_info = (info[0], str(info[1]).title(), str(info[2]).title(), str(info[3]).title(), str(info[4]).capitalize(), info[5], info[6], info[7], info[8])
    return render_template('word_detail.html', page_name='Word '+ word_id, logged_in=is_logged_in(), admin=is_admin(), word_information=word_info)


@app.route('/individual_word/edit/<word_id>', methods=['POST', 'GET'])
def render_edit_word_information(word_id):
    if not is_admin():
        return redirect('/individual_word/' + word_id)
    if request.method == 'POST':
        maori_word = request.form.get('maori_word').lower().strip()
        english_translation = request.form.get('english_translation').lower().strip()
        category = request.form.get('category').lower().strip()
        definition = request.form.get('definition').lower().strip()
        level = request.form.get('level').strip()
        last_edited_time = "123"
        last_edited_user = session['firstname'] + " " + session['lastname']
        image_name = request.form.get('image_name').lower().strip()
        if image_name == "":
            image_name = "none"

        con = create_connection(DATABASE)
        query = "UPDATE vocab_list SET maori_word = ?, english_translation = ?, category = ?, definition = ?, level = ?, last_edited_time = datetime('now','localtime'), last_edited_user = ?, image_name = ? WHERE id = ?"
        cur = con.cursor()
        cur.execute(query, (maori_word, english_translation, category, definition, level, last_edited_user, image_name, word_id))
        con.commit()
        con.close()
        return redirect('/individual_word/' + word_id)

    # Get word information
    con = create_connection(DATABASE)
    query = "SELECT * FROM vocab_list WHERE id = ?"
    cur = con.cursor()
    cur.execute(query, (word_id,))
    word_info = cur.fetchall()
    con.close()

    return render_template('edit_word_information.html', page_name='Edit Word ' + word_id, logged_in=is_logged_in(), admin=is_admin(), word_information=word_info)


@app.route('/login', methods=['POST', 'GET'])
def render_login():
    if is_logged_in():
        return redirect('/')
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()
        con = create_connection(DATABASE)
        query = """SELECT id, first_name, last_name, password, role FROM user WHERE email = ?"""
        cur = con.cursor()
        cur.execute(query, (email,))
        user_data = cur.fetchone()
        con.close()
        # if given the email that is not in the database this will raise an error
        # would be better to find out how to see if the query return an empty result set
        try:
            user_id = user_data[0]
            first_name = user_data[1]
            last_name = user_data[2]
            db_password = user_data[3]
            role = user_data[4]
        except IndexError:
            return redirect("/login?error=Email+invalid+or+password+incorrect")

        if not bcrypt.check_password_hash(db_password, password):
            return redirect(request.referrer + "error=Email+invalid+or+password+incorrect")

        session['email'] = email
        session['userid'] = user_id
        session['firstname'] = first_name
        session['lastname'] = last_name
        session['role'] = role

        return redirect('/')

    return render_template('login.html', page_name='Login', logged_in=is_logged_in(), admin=is_admin())


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
            return redirect("/signup?error=Passwords+do+not+match")

        if len(password) < 8:
            return redirect("/signup?error=Passwords+must+be+at+least+8+characters")

        hashed_password = bcrypt.generate_password_hash(password)
        con = create_connection(DATABASE)
        query = "INSERT INTO user (first_name, last_name, email, password, role) VALUES (?, ?, ?, ?, ?)"
        cur = con.cursor()

        try:
            cur.execute(query, (first_name, last_name, email, hashed_password, "User"))
        except sqlite3.IntegrityError:
            con.close()
            return redirect('/signup?error=Email+is+already+used')

        con.commit()
        con.close()

        return redirect('login')

    return render_template('signup.html', page_name='Sign Up', logged_in=is_logged_in(), admin=is_admin())


# Try make it activate this after signing up as well as after logging in
@app.route('/confirm_school_role/<user_id>')
def render_confirm_school_role(user_id):
    if not in_school():
        return redirect('/')
    return render_template('confirm_school_role.html', page_name='Confirm', user_id=user_id, logged_in=is_logged_in(), admin=is_admin())


@app.route('/signup_student/<user_id>')
def signup_student(user_id):
    con = create_connection(DATABASE)
    query = "UPDATE user SET role='Student' WHERE id = ?"
    cur = con.cursor()
    cur.execute(query, (user_id,))
    con.commit()
    con.close()
    session['role'] = 'Student'
    return redirect('/')


@app.route('/signup_teacher/<user_id>')
def signup_teacher(user_id):
    con = create_connection(DATABASE)
    query = "UPDATE user SET role='Teacher' WHERE id = ?"
    cur = con.cursor()
    cur.execute(query, (user_id,))
    con.commit()
    con.close()
    session['role'] = 'Teacher'
    return redirect('/')


app.run()  # Runs app normally
# app.run(host='0.0.0.0', debug=True)  # Lets other invade your website
