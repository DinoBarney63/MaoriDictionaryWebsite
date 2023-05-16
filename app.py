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


# Check to see if the user is logged in
def is_logged_in():
    if session.get('email') is None:
        return False
    else:
        return True


# Check to see if the user is an admin
def is_admin():
    if is_logged_in():
        if session.get('role') == "Teacher" or session.get('role') == "Admin":
            return True
        else:
            return False
    else:
        return False


# Check to see if the user has a school email
def in_school():
    if is_logged_in():
        email_parts = session.get('email').split('@')
        address_parts = email_parts[1].split('.')
        if "school" in address_parts:
            return True
    else:
        return False


# Gets word info and reformat it
def get_word_info(word_id):
    con = create_connection(DATABASE)
    cur = con.cursor()
    query = "SELECT * FROM vocab_list WHERE id = ?"
    cur.execute(query, (word_id,))
    word_info = cur.fetchall()
    con.close()

    word_info = word_info[0]
    word_info = reformat_word_info(word_info)
    return word_info


# Reformat all the word's info, only can be used for as single word
def reformat_word_info(word):
    word_info = (word[0], str(word[1]).title(), str(word[2]).title(), str(word[3]).title(), str(word[4]).capitalize(),
                 word[5], word[6], word[7], word[8])
    return word_info


# Reformat the word for displaying in the word list
def reformat_word_list(words):
    word_list = []
    for word in words:
        if len(word) == 4:
            word = (word[0], str(word[1]).title(), str(word[2]).title(), str(word[3]).title())
        elif len(word) == 5:
            word = (word[0], str(word[1]).title(), str(word[2]).title(), str(word[3]).title(), str(word[4]))
        word_list.append(word)
    return word_list


# Gets category info and reformat it
def get_category_info(category_id):
    con = create_connection(DATABASE)
    cur = con.cursor()
    query = "SELECT * FROM category WHERE id = ?"
    cur.execute(query, (category_id,))
    category_info = cur.fetchall()
    con.close()

    category_info = reformat_category_list(category_info)
    return category_info[0]


# Reformat the categories to be displayed
def reformat_category_list(categories):
    category_list = []
    for category in categories:
        category = (category[0], str(category[1]).title())
        category_list.append(category)
    return category_list


# Gets level info
def get_level_info(level_id):
    con = create_connection(DATABASE)
    cur = con.cursor()
    query = "SELECT * FROM level WHERE id = ?"
    cur.execute(query, (level_id,))
    level_info = cur.fetchall()
    con.close()

    return level_info[0]


@app.route('/')
def render_home():
    # If the user is in a school but hasn't confirmed their role we redirect them to do so
    if in_school():
        if session['role'] == 'User':
            return redirect('/confirm_school_role/' + str(session['userid']))

    return render_template('home.html', page_name='Home', logged_in=is_logged_in(), admin=is_admin())


@app.route('/word_list/<category_id>_<level_id>')
def render_word_list(category_id, level_id):
    # Gets the category and level lists to be displayed
    con = create_connection(DATABASE)
    cur = con.cursor()
    query = "SELECT id, name FROM category"
    cur.execute(query)
    category_list = cur.fetchall()
    query = "SELECT id, number FROM level"
    cur.execute(query)
    level_list = cur.fetchall()

    category = category_list[int(category_id) - 1][1]
    level = int(level_id)
    # If there is no filter then we select all the words otherwise we select those with the correct filter
    if category_id == "0" and level_id == "0":
        query = "SELECT id, maori_word, english_translation, category, level FROM vocab_list"
        cur.execute(query)
    elif category_id != "0" and level_id == "0":
        query = "SELECT id, maori_word, english_translation, category, level FROM vocab_list WHERE category=?"
        cur.execute(query, (category,))
    elif category_id == "0" and level_id != "0":
        query = "SELECT id, maori_word, english_translation, category, level FROM vocab_list WHERE level=?"
        cur.execute(query, (level,))
    else:
        query = "SELECT id, maori_word, english_translation, category, level FROM vocab_list WHERE category=? AND level=?"
        # Here we need to use an AND not a comma
        cur.execute(query, (category, level))
    word_list = cur.fetchall()
    con.close()

    # Reformatting the words to be displayed
    word_list = reformat_word_list(word_list)
    # Reformatting the categories to be displayed
    category_list = reformat_category_list(category_list)
    return render_template('word_list.html', page_name='Words', logged_in=is_logged_in(), admin=is_admin(),
                           word_list=word_list, category_list=category_list, level_list=level_list,
                           current_category=category_id, current_level=level_id)


@app.route('/add_word', methods=['POST'])
def add_word():
    if not is_admin():
        return redirect('/')

    if request.method == "POST":
        # Reformat the word info to all lowercase
        maori_word = request.form.get('maori_word').lower().strip()
        english_translation = request.form.get('english_translation').lower().strip()
        category = request.form.get('category').lower().strip()
        definition = request.form.get('definition').lower().strip()
        level = request.form.get('level').strip()
        last_edited_user = session['firstname'] + " " + session['lastname']
        image_name = request.form.get('image_name').lower().strip()
        # Converts the empty definition to pending
        if definition == "":
            definition = "pending"
        # Converts the blank image name to none
        if image_name == "":
            image_name = "none"

        con = create_connection(DATABASE)
        cur = con.cursor()
        query = "INSERT INTO vocab_list (maori_word, english_translation, category, definition, level, last_edited_time, last_edited_user, image_name) VALUES (?, ?, ?, ?, ?, datetime('now','localtime'), ?, ?)"
        cur.execute(query, (maori_word, english_translation, category, definition, level, last_edited_user, image_name))
        con.commit()
        con.close()

        return redirect('/admin')


@app.route('/individual_word/<word_id>')
def render_individual_word(word_id):
    # Get word information
    word_info = get_word_info(word_id)
    return render_template('word_detail.html', page_name='Word ' + word_id, logged_in=is_logged_in(), admin=is_admin(),
                           word_information=word_info)


@app.route('/individual_word/edit/<word_id>', methods=['POST', 'GET'])
def render_edit_word_information(word_id):
    if not is_admin():
        return redirect('/individual_word/' + word_id)

    if request.method == 'POST':
        # Reformat the word info to all lowercase
        maori_word = request.form.get('maori_word').lower().strip()
        english_translation = request.form.get('english_translation').lower().strip()
        category = request.form.get('category').lower().strip()
        definition = request.form.get('definition').lower().strip()
        level = request.form.get('level').strip()
        last_edited_user = session['firstname'] + " " + session['lastname']
        image_name = request.form.get('image_name').lower().strip()
        # Converts the empty definition to pending
        if definition == "":
            definition = "pending"
        # Converts the blank image name to none
        if image_name == "":
            image_name = "none"

        con = create_connection(DATABASE)
        cur = con.cursor()
        query = "UPDATE vocab_list SET maori_word = ?, english_translation = ?, category = ?, definition = ?, level = ?, last_edited_time = datetime('now','localtime'), last_edited_user = ?, image_name = ? WHERE id = ?"
        cur.execute(query, (maori_word, english_translation, category, definition, level, last_edited_user, image_name,
                            word_id))
        # Here we needed to organise the variables in the order we want them to be in when they are put into the ?
        con.commit()
        con.close()

        return redirect('/individual_word/' + word_id)

    con = create_connection(DATABASE)
    cur = con.cursor()
    # Get word information
    query = "SELECT * FROM vocab_list WHERE id = ?"
    cur.execute(query, (word_id,))
    word_info = cur.fetchall()
    # Get categories
    query = "SELECT * FROM category"
    cur.execute(query)
    categories = cur.fetchall()
    # Get levels
    query = "SELECT * FROM level"
    cur.execute(query)
    level_list = cur.fetchall()
    con.close()

    # Reformatting the word info to be displayed
    word_info = word_info[0]
    word_info = reformat_word_info(word_info)
    # Reformatting the categories to be displayed
    category_list = reformat_category_list(categories)
    return render_template('edit_word_information.html', page_name='Edit Word ' + word_id, logged_in=is_logged_in(),
                           admin=is_admin(), word_information=word_info, category_list=category_list,
                           level_list=level_list)


@app.route('/individual_word/delete_word/<word_id>')
def render_delete_word(word_id):
    if not is_admin():
        return redirect('/individual_word/' + word_id)

    # Get word information
    word_info = get_word_info(word_id)
    return render_template('delete_confirm.html', page_name='Delete Word ' + word_id, logged_in=is_logged_in(),
                           admin=is_admin(), information=word_info, type='word', name='Word')


@app.route('/individual_word/delete_word_confirm/<word_id>')
def delete_word_confirm(word_id):
    if not is_admin():
        return redirect('/individual_word/' + word_id)

    con = create_connection(DATABASE)
    cur = con.cursor()
    query = "DELETE FROM vocab_list WHERE id = ?"
    cur.execute(query, (word_id,))
    con.commit()
    con.close()

    return redirect("/word_list/0_0")


@app.route('/add_category', methods=['POST'])
def add_category():
    if not is_admin():
        return redirect('/')

    if request.method == "POST":
        # Reformat the category to all lowercase
        category_name = request.form.get('filter_name').lower().strip()

        con = create_connection(DATABASE)
        cur = con.cursor()
        query = "INSERT INTO category (name) VALUES (?)"

        # Checks to see if the category already exists
        try:
            cur.execute(query, (category_name,))
        except sqlite3.IntegrityError:
            con.close()
            return redirect('/category_list?error=Category+already+exists')

        con.commit()
        con.close()

        return redirect('/category_list')

@app.route('/individual_category/<category_id>')
def individual_category(category_id):
    return redirect('/category_list')


@app.route('/individual_category/edit_category/<category_id>', methods=['POST', 'GET'])
def render_edit_category(category_id):
    if not is_admin():
        return redirect('/')

    # Get category info
    category_info = get_category_info(category_id)

    category = (category_info[1]).lower()
    con = create_connection(DATABASE)
    cur = con.cursor()
    query = "SELECT id, maori_word, english_translation, category FROM vocab_list WHERE category=?"
    cur.execute(query, (category,))
    word_list = cur.fetchall()
    con.close()

    if request.method == 'POST':
        # Reformat the name to all lowercase
        category_name = request.form.get('filter_name').lower().strip()

        con = create_connection(DATABASE)
        cur = con.cursor()

        # Edit all words in word list
        for word in word_list:
            word_id = word[0]
            query = "UPDATE vocab_list SET category = ? WHERE id = ?"
            cur.execute(query, (category_name, word_id))
            con.commit()

        # Updates the category
        query = "UPDATE category SET name = ? WHERE id = ?"
        cur.execute(query, (category_name, category_id))
        con.commit()
        con.close()

        return redirect('/category_list')

    # Reformatting the words to be displayed
    word_list = reformat_word_list(word_list)
    return render_template('edit_filter.html', page_name='Edit Category' + category_id, logged_in=is_logged_in(),
                           admin=is_admin(), information=category_info, type='category', name='Category', affected_words=word_list)


@app.route('/individual_category/delete_category/<category_id>')
def render_delete_category(category_id):
    if not is_admin():
        return redirect('/')

    # Get category info
    category_info = get_category_info(category_id)

    category = (category_info[1]).lower()
    con = create_connection(DATABASE)
    cur = con.cursor()
    query = "SELECT id, maori_word, english_translation, category FROM vocab_list WHERE category=?"
    cur.execute(query, (category,))
    word_list = cur.fetchall()
    con.close()

    # Reformatting the words to be displayed
    word_list = reformat_word_list(word_list)
    return render_template('delete_confirm.html', page_name='Delete Category ' + category_id, logged_in=is_logged_in(),
                           admin=is_admin(), information=category_info, type='category', name='Category', affected_words=word_list)


@app.route('/individual_category/delete_category_confirm/<category_id>')
def delete_category_confirm(category_id):
    if not is_admin():
        return redirect('/')

    # Get category info
    category_info = get_category_info(category_id)

    category = (category_info[1]).lower()
    con = create_connection(DATABASE)
    cur = con.cursor()
    query = "SELECT id, maori_word, english_translation, category FROM vocab_list WHERE category=?"
    cur.execute(query, (category,))
    word_list = cur.fetchall()

    # Edit all words in word list
    for word in word_list:
        word_id = word[0]
        query = "UPDATE vocab_list SET category = null WHERE id = ?"
        cur.execute(query, (word_id, ))
        con.commit()

    # Deletes the category
    query = "DELETE FROM category WHERE id = ?"
    cur.execute(query, (category_id,))
    con.commit()
    con.close()

    return redirect("/")


@app.route('/add_level', methods=['POST'])
def add_level():
    if not is_admin():
        return redirect('/')

    if request.method == "POST":
        level_number = request.form.get('filter_number')

        con = create_connection(DATABASE)
        cur = con.cursor()
        query = "INSERT INTO level (number) VALUES (?)"

        # Checks to see if the level already exists
        try:
            cur.execute(query, (level_number,))
        except sqlite3.IntegrityError:
            con.close()
            return redirect('/level_list?error=Level+already+exists')

        con.commit()
        con.close()

        return redirect('/level_list')


@app.route('/individual_level/<level_id>')
def individual_level(level_id):
    return redirect('/level_list')


@app.route('/individual_level/edit_level/<level_id>', methods=['POST', 'GET'])
def render_edit_level(level_id):
    if not is_admin():
        return redirect('/')

    # Get Level info
    level_info = get_level_info(level_id)

    level = (level_info[1])
    con = create_connection(DATABASE)
    cur = con.cursor()
    query = "SELECT id, maori_word, english_translation, level FROM vocab_list WHERE level=?"
    cur.execute(query, (level,))
    word_list = cur.fetchall()
    con.close()

    if request.method == 'POST':
        # Reformat the name to all lowercase
        level_number = request.form.get('filter_number').strip()

        con = create_connection(DATABASE)
        cur = con.cursor()

        # Edit all words in word list
        for word in word_list:
            word_id = word[0]
            query = "UPDATE vocab_list SET level = ? WHERE id = ?"
            cur.execute(query, (level_number, word_id))
            con.commit()

        # Updates the level
        query = "UPDATE level SET number = ? WHERE id = ?"
        cur.execute(query, (level_number, level_id))
        con.commit()
        con.close()

        return redirect('/level_list')

    # Reformatting the words to be displayed
    word_list = reformat_word_list(word_list)
    return render_template('edit_filter.html', page_name='Edit Level' + level_id, logged_in=is_logged_in(),
                           admin=is_admin(), information=level_info, type='level', name='Level', affected_words=word_list)


@app.route('/individual_level/delete_level/<level_id>')
def render_delete_level(level_id):
    if not is_admin():
        return redirect('/')

    # Get Level info
    level_info = get_level_info(level_id)

    level = (level_info[1])
    con = create_connection(DATABASE)
    cur = con.cursor()
    query = "SELECT id, maori_word, english_translation, level FROM vocab_list WHERE level=?"
    cur.execute(query, (level,))
    word_list = cur.fetchall()
    con.close()

    # Reformatting the words to be displayed
    word_list = reformat_word_list(word_list)
    return render_template('delete_confirm.html', page_name='Delete Level ' + level_id, logged_in=is_logged_in(),
                           admin=is_admin(), information=level_info, type='level', name='Level', affected_words=word_list)


@app.route('/individual_level/delete_level_confirm/<level_id>')
def delete_level_confirm(level_id):
    if not is_admin():
        return redirect('/')

    # Get Level info
    level_info = get_level_info(level_id)

    level = (level_info[1])
    con = create_connection(DATABASE)
    cur = con.cursor()
    query = "SELECT id, maori_word, english_translation, level FROM vocab_list WHERE level=?"
    cur.execute(query, (level,))
    word_list = cur.fetchall()

    # Edit all words in word list
    for word in word_list:
        word_id = word[0]
        query = "UPDATE vocab_list SET level = null WHERE id = ?"
        cur.execute(query, (word_id,))
        con.commit()

    # Deletes the category
    query = "DELETE FROM level WHERE id = ?"
    cur.execute(query, (level_id,))
    con.commit()
    con.close()

    return redirect("/")


@app.route('/admin')
def render_admin():
    if not is_admin():
        return redirect('/')

    con = create_connection(DATABASE)
    cur = con.cursor()
    query = "SELECT id, maori_word, english_translation, category, level FROM vocab_list"
    cur.execute(query)
    words = cur.fetchall()
    query = "SELECT * FROM category"
    cur.execute(query)
    categories = cur.fetchall()
    query = "SELECT * FROM level"
    cur.execute(query)
    level_list = cur.fetchall()
    query = "SELECT * FROM user"
    cur.execute(query)
    user_list = cur.fetchall()
    con.close()

    # Reformatting the words to be displayed
    word_list = reformat_word_list(words)
    # Reformatting the categories to be displayed
    category_list = reformat_category_list(categories)
    return render_template("admin.html", page_name='Admin', logged_in=is_logged_in(), admin=is_admin(),
                           word_list=word_list, category_list=category_list, level_list=level_list, user_list=user_list)


@app.route('/login', methods=['POST', 'GET'])
def render_login():
    if is_logged_in():
        return redirect('/')

    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()
        con = create_connection(DATABASE)
        cur = con.cursor()
        query = """SELECT id, first_name, last_name, password, role FROM user WHERE email = ?"""
        cur.execute(query, (email,))
        user_data = cur.fetchone()
        con.close()

        if user_data is None:
            return redirect("/login?error=Invalid+email+or+incorrect+password")

        user_id = user_data[0]
        first_name = user_data[1]
        last_name = user_data[2]
        db_password = user_data[3]
        role = user_data[4]

        if not bcrypt.check_password_hash(db_password, password):
            return redirect("/login?error=Invalid+email+or+incorrect+password")

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
        # Reformat the user info
        first_name = request.form.get('first_name').title().strip()
        last_name = request.form.get('last_name').title().strip()
        email = request.form.get('email').lower().strip()
        password = request.form.get('password')
        password2 = request.form.get('password2')

        if len(password) < 8:
            return redirect("/signup?error=Passwords+must+be+at+least+8+characters")

        if password != password2:
            return redirect("/signup?error=Passwords+do+not+match")

        # Hashes the password
        hashed_password = bcrypt.generate_password_hash(password)
        con = create_connection(DATABASE)
        cur = con.cursor()
        query = "INSERT INTO user (first_name, last_name, email, password, role) VALUES (?, ?, ?, ?, ?)"

        # Checks to see if the email has already been used
        try:
            cur.execute(query, (first_name, last_name, email, hashed_password, "User"))
        except sqlite3.IntegrityError:
            con.close()
            return redirect('/signup?error=Email+is+already+used')

        con.commit()
        con.close()

        return redirect('login')

    return render_template('signup.html', page_name='Sign Up', logged_in=is_logged_in(), admin=is_admin())


# This occurs if the user has a school email but hasn't become a student or teacher user
@app.route('/confirm_school_role/<user_id>')
def render_confirm_school_role(user_id):
    if not in_school():
        return redirect('/')

    return render_template('confirm_school_role.html', page_name='Confirm', user_id=user_id, logged_in=is_logged_in(),
                           admin=is_admin())


@app.route('/signup_student/<user_id>')
def signup_student(user_id):
    con = create_connection(DATABASE)
    cur = con.cursor()
    query = "UPDATE user SET role='Student' WHERE id = ?"
    cur.execute(query, (user_id,))
    con.commit()
    con.close()
    session['role'] = 'Student'

    return redirect('/')


@app.route('/signup_teacher/<user_id>')
def signup_teacher(user_id):
    con = create_connection(DATABASE)
    cur = con.cursor()
    query = "UPDATE user SET role='Teacher' WHERE id = ?"
    cur.execute(query, (user_id,))
    con.commit()
    con.close()
    session['role'] = 'Teacher'

    return redirect('/')


app.run()  # Runs app normally
# app.run(host='0.0.0.0', debug=True)  # Lets other invade your website
