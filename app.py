from flask import Flask, render_template, redirect, request, session
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt

DATABASE = "C:/Users/19164/PycharmProjects/Pycharm---MaoriDictionaryWebsite/MDW.db"  # School Computer
# DATABASE = "C:/Users/ryanj/PycharmProjects/Pycharm---MaoriDictionaryWebsite/MDW.db"  # Home Laptop

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
        if session.get('is_admin') == 1:
            return True
    return False


@app.route('/')
def render_home():
    return render_template('home.html', logged_in=is_logged_in(), admin=is_admin())


@app.route('/words/<category_id>')
def render_words(category_id):
    con = create_connection(DATABASE)
    if category_id == "0":
        query = "SELECT word, description, image, level, category FROM words"
        cur = con.cursor()
        cur.execute(query)
        word_list = cur.fetchall()
    else:
        query = "SELECT word, description, image, level, category FROM words WHERE category_id=?"
        cur = con.cursor()
        cur.execute(query, (category_id, ))
        word_list = cur.fetchall()
    query = "SELECT id, name FROM category"
    cur = con.cursor()
    cur.execute(query)
    category_list = cur.fetchall()
    con.close()
    return render_template('words.html', words=word_list, categories=category_list, logged_in=is_logged_in(),
                           admin=is_admin())


@app.route('/login', methods=['POST', 'GET'])
def render_login():
    if is_logged_in():
        return redirect('/menu/0')
    print("Logging in")
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()
        con = create_connection(DATABASE)
        query = """SELECT id, fname, password, is_admin FROM user WHERE email = ?"""
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
            admin = user_data[3]
        except IndexError:
            return redirect("/login?error=Email+invalid+or+password+incorrect")

        if not bcrypt.check_password_hash(db_password, password):
            return redirect(request.referrer + "error=Email+invalid+or+password+incorrect")

        session['email'] = email
        session['userid'] = user_id
        session['firstname'] = first_name
        session['is_admin'] = admin

        print(session)
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
        fname = request.form.get('fname').title().strip()
        lname = request.form.get('lname').title().strip()
        email = request.form.get('email').lower().strip()
        password = request.form.get('password')
        password2 = request.form.get('password2')

        if password != password2:
            return redirect("\signup?error=Passwords+do+not+match")

        if len(password) < 8:
            return redirect("\signup?error=Passwords+must+be+at+least+8+characters")

        hashed_password = bcrypt.generate_password_hash(password)
        con = create_connection(DATABASE)
        query = "INSERT INTO user (fname, lname, email, password, is_admin) VALUES (?, ?, ?, ?, ?)"
        cur = con.cursor()

        try:
            cur.execute(query, (fname, lname, email, hashed_password, "0"))
        except sqlite3.IntegrityError:
            con.close()
            return redirect('\signup?error=Email+is+already+used')

        con.commit()
        con.close()

        return redirect("login")

    return render_template('signup.html', logged_in=is_logged_in())


@app.route('/admin')
def render_admin():
    if not is_logged_in():
        return redirect('/?message=Need+to+be+logged+in.')
    if not is_admin():
        return redirect('/?message=Not+an+admin.')
    con = create_connection(DATABASE)
    query = "SELECT * FROM words"
    cur = con.cursor()
    cur.execute(query)
    word_list = cur.fetchall()
    query = "SELECT * FROM category"
    cur = con.cursor()
    cur.execute(query)
    category_list = cur.fetchall()
    query = "SELECT * FROM user"
    cur = con.cursor()
    cur.execute(query)
    user_list = cur.fetchall()
    con.close()
    return render_template("admin.html", logged_in=is_logged_in(), admin=is_admin(), words=word_list,
                           categories=category_list, users=user_list, active_user=session)


@app.route('/add_category', methods=['POST'])
def add_category():
    if not is_logged_in():
        return redirect('/?message=Need+to+be+logged+in.')
    if request.method == "POST":
        category_name = request.form.get('name').title().strip()
        con = create_connection(DATABASE)
        query = "INSERT INTO category ('name') VALUES (?)"
        cur = con.cursor()
        cur.execute(query, (category_name, ))
        con.commit()
        con.close()
        return redirect('/admin')


@app.route('/delete_category', methods=['POST'])
def render_delete_category():
    if not is_logged_in():
        return redirect('/?message=Need+to+be+logged+in.')
    if request.method == "POST":
        category = request.form.get('category_id')
        category = category.split(", ")
        category_id = category[0]
        category_name = category[1]
        return render_template("delete_confirm.html", id=category_id, name=category_name, type="category")
    return redirect("/admin")


@app.route('/delete_category_confirm/<category_id>')
def delete_category_confirm(category_id):
    if not is_logged_in():
        return redirect('/?message=Need+to+be+logged+in.')
    con = create_connection(DATABASE)
    query = "DELETE FROM category WHERE id = ?"
    cur = con.cursor()
    cur.execute(query, (category_id,))
    con.commit()
    con.close()
    return redirect("/admin")


@app.route('/add_word', methods=['POST'])
def add_word():
    if not is_logged_in():
        return redirect('/?message=Need+to+be+logged+in.')
    if request.method == "POST":
        name = request.form.get('name').title().strip()
        description = request.form.get('description').capitalize().strip()
        volume = request.form.get('volume').strip() + " ml"
        image = request.form.get('image').lower().strip()
        price = request.form.get('price').strip()
        category_id = request.form.get('word_category_id').title().strip()
        category_id = category_id[0]
        con = create_connection(DATABASE)
        query = "INSERT INTO words (name, description, volume, image, price, category_id) VALUES (?, ?, ?, ?, ?, ?)"
        cur = con.cursor()
        cur.execute(query, (name, description, volume, image, price, category_id))
        con.commit()
        con.close()
        return redirect('/admin')


@app.route('/delete_word', methods=['POST'])
def render_delete_word():
    if not is_logged_in():
        return redirect('/?message=Need+to+be+logged+in.')
    if request.method == "POST":
        word = request.form.get('word_id')
        word = word.split(", ")
        word_id = word[0]
        word_name = word[1]
        return render_template("delete_confirm.html", id=word_id, name=word_name, type="word")
    return redirect("/admin")


@app.route('/delete_word_confirm/<word_id>')
def delete_word_confirm(word_id):
    if not is_logged_in():
        return redirect('/?message=Need+to+be+logged+in.')
    con = create_connection(DATABASE)
    query = "DELETE FROM words WHERE id = ?"
    cur = con.cursor()
    cur.execute(query, (word_id,))
    con.commit()
    con.close()
    return redirect("/admin")


@app.route('/promote_user', methods=['POST'])
def promote_user():
    if not is_logged_in():
        return redirect('/?message=Need+to+be+logged+in.')
    if request.method == "POST":
        user = request.form.get('promote_user_id')
        user = user.split(", ")
        user_id = user[0]
        user_name = user[1]
        return render_template("change_user_permissions_confirm.html", id=user_id, name=user_name, action="promote")
    return redirect("/admin")


@app.route('/promote_user_confirm/<user_id>')
def promote_user_confirm(user_id):
    if not is_logged_in():
        return redirect('/?message=Need+to+be+logged+in.')
    con = create_connection(DATABASE)
    query = "UPDATE user SET is_admin='1' WHERE id = ?"
    cur = con.cursor()
    cur.execute(query, (user_id, ))
    con.commit()
    con.close()
    return redirect("/admin")


@app.route('/demote_user', methods=['POST'])
def demote_user():
    if not is_logged_in():
        return redirect('/?message=Need+to+be+logged+in.')
    if request.method == "POST":
        user = request.form.get('demote_user_id')
        user = user.split(", ")
        user_id = user[0]
        user_name = user[1]
        return render_template("change_user_permissions_confirm.html", id=user_id, name=user_name, action="demote")
    return redirect("/admin")


@app.route('/demote_user_confirm/<user_id>')
def demote_user_confirm(user_id):
    if not is_logged_in():
        return redirect('/?message=Need+to+be+logged+in.')
    con = create_connection(DATABASE)
    query = "UPDATE user SET is_admin='0' WHERE id = ?"
    cur = con.cursor()
    cur.execute(query, (user_id, ))
    con.commit()
    con.close()
    return redirect("/admin")


@app.route('/delete_user', methods=['POST'])
def render_delete_user():
    if not is_logged_in():
        return redirect('/?message=Need+to+be+logged+in.')
    if request.method == "POST":
        user = request.form.get('user_id')
        user = user.split(", ")
        user_id = user[0]
        user_name = user[1]
        return render_template("delete_confirm.html", id=user_id, name=user_name, type="user")
    return redirect("/admin")


@app.route('/delete_user_confirm/<user_id>')
def delete_user_confirm(user_id):
    if not is_logged_in():
        return redirect('/?message=Need+to+be+logged+in.')
    con = create_connection(DATABASE)
    query = "DELETE FROM user WHERE id = ?"
    cur = con.cursor()
    cur.execute(query, (user_id,))
    con.commit()
    con.close()
    return redirect("/admin")


app.run()  # Runs app normally
# app.run(host='0.0.0.0', debug=True)  # Lets other invade your website
