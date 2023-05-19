from flask import Flask, render_template, redirect, request, session
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt

DATABASE = "C:/Users/19164/PycharmProjects/Pycharm---MaoriDictionaryWebsite/MaoriDictionary.db"  # School Computer
# DATABASE = "C:/Users/ryanj/PycharmProjects/Pycharm---MaoriDictionaryWebsite/MaoriDictionary.db"  # Home Laptop

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "Key123"  # Whatever you want


# Creates a connection to the database with the database provided
def create_connection(db_file):
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(e)
    return None


# Executes a database action based on the query and execution provided and will return data if required
def execute_database_action(query, execute):
    connection = create_connection(DATABASE)
    cursor = connection.cursor()
    if execute is None:
        cursor.execute(query)
    else:
        cursor.execute(query, execute)
    data = cursor.fetchall()
    connection.close()
    return data


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
    query = "SELECT * FROM vocab_list WHERE id = ?"
    execute = (word_id,)
    word_info = execute_database_action(query=query, execute=execute)

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
    query = "SELECT * FROM category WHERE id = ?"
    execute = (category_id,)
    category_info = execute_database_action(query=query, execute=execute)

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
    query = "SELECT * FROM level WHERE id = ?"
    execute = (level_id,)
    level_info = execute_database_action(query=query, execute=execute)

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
    execute = None
    query = "SELECT id, name FROM category"
    category_list = execute_database_action(query=query, execute=execute)
    query = "SELECT id, number FROM level"
    level_list = execute_database_action(query=query, execute=execute)

    category = category_list[int(category_id) - 1][1]
    level = int(level_id)
    # If there is no filter then we select all the words otherwise we select those with the correct filter
    if category_id == "0" and level_id == "0":
        query = "SELECT id, maori_word, english_translation, category, level FROM vocab_list"
        execute = None
    elif category_id != "0" and level_id == "0":
        query = "SELECT id, maori_word, english_translation, category, level FROM vocab_list WHERE category=?"
        execute = (category,)
    elif category_id == "0" and level_id != "0":
        query = "SELECT id, maori_word, english_translation, category, level FROM vocab_list WHERE level=?"
        execute = (level,)
    else:
        query = "SELECT id, maori_word, english_translation, category, level FROM vocab_list WHERE category=? AND level=?"
        # Here we need to use an AND not a comma
        execute = (category, level)
    word_list = execute_database_action(query=query, execute=execute)

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

        query = "INSERT INTO vocab_list (maori_word, english_translation, category, definition, level, last_edited_time, last_edited_user, image_name) VALUES (?, ?, ?, ?, ?, datetime('now','localtime'), ?, ?)"
        execute = (maori_word, english_translation, category, definition, level, last_edited_user, image_name)
        execute_database_action(query=query, execute=execute)

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

        query = "UPDATE vocab_list SET maori_word = ?, english_translation = ?, category = ?, definition = ?, level = ?, last_edited_time = datetime('now','localtime'), last_edited_user = ?, image_name = ? WHERE id = ?"
        execute = (maori_word, english_translation, category, definition, level, last_edited_user, image_name,
                            word_id)
        # Here we needed to organise the variables in the order we want them to be in when they are put into the ?
        execute_database_action(query=query, execute=execute)

        return redirect('/individual_word/' + word_id)

    # Get word information
    query = "SELECT * FROM vocab_list WHERE id = ?"
    execute = (query, (word_id,))
    word_info = execute_database_action(query=query, execute=execute)

    # Get categories
    query = "SELECT * FROM category"
    execute = None
    categories = execute_database_action(query=query, execute=execute)
    # Get levels
    query = "SELECT * FROM level"
    execute = None
    level_list = execute_database_action(query=query, execute=execute)

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

    query = "DELETE FROM vocab_list WHERE id = ?"
    execute = (word_id,)
    execute_database_action(query=query, execute=execute)

    return redirect("/word_list/0_0")


@app.route('/add_category', methods=['POST'])
def add_category():
    if not is_admin():
        return redirect('/')

    if request.method == "POST":
        # Reformat the category to all lowercase
        category_name = request.form.get('category_name').lower().strip()

        if not category_name.isalpha():
            return redirect("/admin?error=Category+can+only+contain+letters")

        query = "INSERT INTO category (name) VALUES (?)"
        execute = (category_name,)

        # Checks to see if the category already exists
        try:
            execute_database_action(query=query, execute=execute)
        except sqlite3.IntegrityError:
            return redirect('/admin?error=Category+already+exists')

        return redirect('/admin')


@app.route('/individual_category/<category_id>')
def individual_category(category_id):
    return redirect('/admin')


@app.route('/individual_category/edit_category/<category_id>', methods=['POST', 'GET'])
def render_edit_category(category_id):
    if not is_admin():
        return redirect('/')

    # Get category info
    category_info = get_category_info(category_id)

    category = (category_info[1]).lower()
    query = "SELECT id, maori_word, english_translation, category FROM vocab_list WHERE category=?"
    execute = (category,)
    word_list = execute_database_action(query=query, execute=execute)

    if request.method == 'POST':
        # Reformat the name to all lowercase
        category_name = request.form.get('filter_name').lower().strip()

        if not category_name.isalpha():
            return redirect("/individual_category/edit_category/" + category_id + "?error=Category+can+only+contain+letters")

        # Edit all words in word list
        for word in word_list:
            word_id = word[0]
            query = "UPDATE vocab_list SET category = ? WHERE id = ?"
            execute = (category_name, word_id)
            execute_database_action(query=query, execute=execute)

        # Updates the category
        query = "UPDATE category SET name = ? WHERE id = ?"
        execute = (category_name, category_id)
        execute_database_action(query=query, execute=execute)

        return redirect('/admin')

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
    query = "SELECT id, maori_word, english_translation, category FROM vocab_list WHERE category=?"
    execute = (category,)
    word_list = execute_database_action(query=query, execute=execute)

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
    query = "SELECT id, maori_word, english_translation, category FROM vocab_list WHERE category=?"
    execute = (category,)
    word_list = execute_database_action(query=query, execute=execute)

    # Edit all words in word list
    for word in word_list:
        word_id = word[0]
        query = "UPDATE vocab_list SET category = null WHERE id = ?"
        execute = (word_id, )
        execute_database_action(query=query, execute=execute)

    # Deletes the category
    query = "DELETE FROM category WHERE id = ?"
    execute = (category_id,)
    execute_database_action(query=query, execute=execute)

    return redirect("/")


@app.route('/add_level', methods=['POST'])
def add_level():
    if not is_admin():
        return redirect('/')

    if request.method == "POST":
        level_number = request.form.get('level_number')

        query = "INSERT INTO level (number) VALUES (?)"
        execute = (level_number,)

        # Checks to see if the level already exists
        try:
            execute_database_action(query=query, execute=execute)
        except sqlite3.IntegrityError:
            return redirect('/admin?error=Level+already+exists')

        return redirect('/admin')


@app.route('/individual_level/<level_id>')
def individual_level(level_id):
    return redirect('/admin')


@app.route('/individual_level/edit_level/<level_id>', methods=['POST', 'GET'])
def render_edit_level(level_id):
    if not is_admin():
        return redirect('/')

    # Get Level info
    level_info = get_level_info(level_id)

    level = (level_info[1])
    query = "SELECT id, maori_word, english_translation, level FROM vocab_list WHERE level=?"
    execute = (level,)
    word_list = execute_database_action(query=query, execute=execute)

    if request.method == 'POST':
        # Reformat the name to all lowercase
        level_number = request.form.get('filter_number').strip()

        # Edit all words in word list
        for word in word_list:
            word_id = word[0]
            query = "UPDATE vocab_list SET level = ? WHERE id = ?"
            execute = (level_number, word_id)
            execute_database_action(query=query, execute=execute)

        # Updates the level
        query = "UPDATE level SET number = ? WHERE id = ?"
        execute = (level_number, level_id)
        execute_database_action(query=query, execute=execute)

        return redirect('/admin')

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
    query = "SELECT id, maori_word, english_translation, level FROM vocab_list WHERE level=?"
    execute = (level,)
    word_list = execute_database_action(query=query, execute=execute)

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
    query = "SELECT id, maori_word, english_translation, level FROM vocab_list WHERE level=?"
    execute = (level,)
    word_list = execute_database_action(query=query, execute=execute)

    # Edit all words in word list
    for word in word_list:
        word_id = word[0]
        query = "UPDATE vocab_list SET level = null WHERE id = ?"
        execute = (word_id,)
        execute_database_action(query=query, execute=execute)

    # Deletes the category
    query = "DELETE FROM level WHERE id = ?"
    execute = (level_id,)
    execute_database_action(query=query, execute=execute)

    return redirect("/")


@app.route('/individual_user/edit_user/<user_id>', methods=['POST', 'GET'])
def render_edit_user(user_id):
    if not is_admin():
        return redirect('/')

    if request.method == 'POST':
        first_name = request.form.get('first_name').title().strip()
        last_name = request.form.get('last_name').title().strip()
        role = request.form.get('role')

        query = "UPDATE user SET first_name = ?, last_name = ?, role = ? WHERE id = ?"
        execute = (first_name, last_name, role, user_id)
        execute_database_action(query=query, execute=execute)

        return redirect('/admin')

    query = "SELECT id, first_name, last_name, email, role FROM user WHERE id=?"
    execute = (user_id,)
    user_info = execute_database_action(query=query, execute=execute)
    user_info = user_info[0]

    return render_template("edit_user_information.html", page_name='Edit User ' + user_id, logged_in=is_logged_in(),
                           admin=is_admin(), user_information=user_info, roles=['User', 'Student', 'Teacher', 'Admin'])



@app.route('/individual_user/delete_user/<user_id>')
def render_delete_user(user_id):
    if not is_admin():
        return redirect('/')

    query = "SELECT id, first_name, last_name, email FROM user WHERE id=?"
    execute = (user_id,)
    user_info = execute_database_action(query=query, execute=execute)
    user_info = user_info[0]

    return render_template('delete_confirm.html', page_name='Delete User ' + user_id, logged_in=is_logged_in(),
                           admin=is_admin(), information=user_info, type='user', name='User')


@app.route('/individual_user/delete_user_confirm/<user_id>')
def delete_user_confirm(user_id):
    if not is_admin():
        return redirect('/')

    query = "DELETE FROM user WHERE id = ?"
    execute = (user_id,)
    execute_database_action(query=query, execute=execute)

    return redirect("/admin")


@app.route('/admin')
def render_admin():
    if not is_admin():
        return redirect('/')

    query = "SELECT id, maori_word, english_translation, category, level FROM vocab_list"
    execute = None
    words = execute_database_action(query=query, execute=execute)
    query = "SELECT * FROM category"
    execute = None
    categories = execute_database_action(query=query, execute=execute)
    query = "SELECT * FROM level"
    execute = None
    level_list = execute_database_action(query=query, execute=execute)
    query = "SELECT * FROM user"
    execute = None
    user_list = execute_database_action(query=query, execute=execute)

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
        query = """SELECT id, first_name, last_name, password, role FROM user WHERE email = ?"""
        execute = (email,)
        user_data = execute_database_action(query=query, execute=execute)
        user_data = user_data[0]

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

        if not first_name.isalpha() and not last_name.isalpha():
            return redirect("/signup?error=First+name+and+last+name+can+only+contain+letters")
        elif not first_name.isalpha():
            return redirect("/signup?error=First+name+can+only+contain+letters")
        elif not last_name.isalpha():
            return redirect("/signup?error=Last+name+can+only+contain_letters")

        if len(password) < 8:
            return redirect("/signup?error=Passwords+must+be+at+least+8+characters")

        if password != password2:
            return redirect("/signup?error=Passwords+do+not+match")

        # Hashes the password
        hashed_password = bcrypt.generate_password_hash(password)
        query = "INSERT INTO user (first_name, last_name, email, password, role) VALUES (?, ?, ?, ?, ?)"
        execute = (first_name, last_name, email, hashed_password, "User")

        # Checks to see if the email has already been used
        try:
            execute_database_action(query=query, execute=execute)
        except sqlite3.IntegrityError:
            return redirect('/signup?error=Email+is+already+used')

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
    query = "UPDATE user SET role='Student' WHERE id = ?"
    execute = (user_id,)
    execute_database_action(query=query, execute=execute)
    session['role'] = 'Student'

    return redirect('/')


@app.route('/signup_teacher/<user_id>')
def signup_teacher(user_id):
    query = "UPDATE user SET role='Teacher' WHERE id = ?"
    execute = (user_id,)
    execute_database_action(query=query, execute=execute)
    session['role'] = 'Teacher'

    return redirect('/')


app.run()  # Runs app normally
# app.run(host='0.0.0.0', debug=True)  # Lets other invade your website
