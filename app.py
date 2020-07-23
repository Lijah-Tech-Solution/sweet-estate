from flask import Flask, render_template, request, redirect, flash, url_for, session, logging
from flask_mysqldb import MySQL
from wtforms import Form, FormField, TextAreaField, PasswordField, validators, StringField
from passlib.hash import sha256_crypt
import os
from functools import wraps
from werkzeug.utils import secure_filename

app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'eportal4school'
app.config['MYSQL_DB'] = 'sweet_estate'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['FLASK_ENV'] = 'development'


# Initialize MYSQL
mysql = MySQL(app)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # get form fields
        username = request.form['username']
        password_c = request.form['password']

        # create cursor
        cur = mysql.connection.cursor()

        # get user by username

        result = cur.execute(
            "SELECT * FROM users WHERE username = %s ", [username])

        if result > 0:
            # get stored hash
            data = cur.fetchone()
            password = data['password']

            # compare passwords
            if sha256_crypt.verify(password_c, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))

            else:
                error = 'Invalid Login'
                return render_template('login.html', error=error)
                # close connection
            cur.close()
        else:
            error = 'Username Not found'
            return render_template('login.html', error=error)
    return render_template('login.html')
# Check if User is Logged in


def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please Login', 'danger')
            return redirect(url_for('login'))
    return wrap


# Register Form Class
class RegisterForm(Form):
    name = StringField(u'Name', validators=[
                       validators.input_required(), validators.Length(min=1, max=50)])
    username = StringField(u'Username', validators=[
                           validators.input_required(), validators.Length(min=1, max=50)])
    email = StringField(u'Email', validators=[
                        validators.input_required(), validators.Length(min=6, max=50)])
    password = PasswordField(u'Password', validators=[
        validators.Length(min=6, max=50),
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField(u'Confirm Password')


# User Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Creating and executing Cursor
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users(name, username, email, password) VALUES(%s, %s, %s, %s)",
                    (name, username, email, password))

        # Commiting the Database
        mysql.connection.commit()

        # Closing the Cursor
        cur.close()

        flash('New User created Succesfully', 'success')
        return redirect(url_for('dashboard'))
    return render_template('register.html', form=form)


# Register Form Class
class CustomerForm(Form):
    name = StringField(u'Name', validators=[
                       validators.input_required(), validators.Length(min=1, max=50)])

    total_amount = StringField(u'total_amount', validators=[
        validators.input_required(), validators.Length(min=1, max=50)])

    email = StringField(u'Email', validators=[
                        validators.input_required(), validators.Length(min=6, max=50)])
    mobile = StringField(u'Mobile', validators=[
        validators.input_required(), validators.Length(min=6, max=50)])
    nok_name = StringField(u'nok_name', validators=[
        validators.input_required(), validators.Length(min=6, max=50)])
    nok_email = StringField(u'nok_email', validators=[
        validators.input_required(), validators.Length(min=6, max=50)])


# New customer Route
@app.route('/new_customer', methods=['GET', 'POST'])
@is_logged_in
def new_customer():
    form = CustomerForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        mobile = form.mobile.data
        nok_name = form.nok_name.data
        nok_email = form.nok_email.data
        total_amount = form.total_amount.data

        # Creating and executing Cursor
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO customers(name, email, mobile, nok_name, nok_email, total_amount) VALUES(%s, %s, %s,%s, %s, %s)",
                    (name, email, mobile, nok_name, nok_email, total_amount))

        # Commiting the Database
        mysql.connection.commit()

        # Closing the Cursor
        cur.close()

        flash('Customer created Succesfully', 'success')
        return redirect(url_for('dashboard'))
    return render_template('new_customer.html', form=form)

# User Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # get form fields
        username = request.form['username']
        password_c = request.form['password']

        # create cursor
        cur = mysql.connection.cursor()

        # get user by username

        result = cur.execute(
            "SELECT * FROM users WHERE username = %s ", [username])

        if result > 0:
            # get stored hash
            data = cur.fetchone()
            password = data['password']

            # compare passwords
            if sha256_crypt.verify(password_c, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))

            else:
                error = 'Invalid Login'
                return render_template('login.html', error=error)
                # close connection
            cur.close()
        else:
            error = 'Username Not found'
            return render_template('login.html', error=error)
    return render_template('login.html')


# Logout Route
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# Dashboard Route
@app.route('/dashboard')
@is_logged_in
def dashboard():
    # Create Cursor
    cur = mysql.connection.cursor()
    # Get Articles
    result = cur.execute("SELECT * FROM customers")
    users = cur.fetchall()
    if result > 0:
        return render_template('dashboard.html', users=users)
    else:
        msg = 'No Articles found'
        return render_template('dashboard.html', msg=msg)
    # Close Connection
    cur.close()


class UserPayment(Form):
    total_amount = StringField(u'Update Payment', validators=[
        validators.input_required()])
    # author = StringField(u'Author', validators=[validators.Length(min=1, max=100)])


# Update Payment Route
@app.route('/update_payment/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def update_payment(id):
    # Create cursor
    cur = mysql.connection.cursor()
    # Get article by ID
    result = cur.execute("SELECT * FROM customers WHERE id = %s", [id])
    cost = cur.fetchone()

    # Get form
    form = UserPayment(request.form)

    # Populate the fields
    form.total_amount.data = cost['total_amount']

    if request.method == 'POST' and form.validate():

        new_cost = request.form['total_amount']
        # logic
        sum = int(form.total_amount.data) - int(new_cost)
        # Create cursor
        cur = mysql.connection.cursor()
        # Execute
        cur.execute(
            "UPDATE customers SET total_amount=%s WHERE id = %s", (sum, id))
        # Commit to DB
        mysql.connection.commit()
        # Close connection
        cur.close()
        flash('Payment Updated successfully', 'success')
        return redirect(url_for('dashboard'))
    return render_template('update_payment.html', form=form)


if __name__ == "__main__":
    # app.secret_key = "hdhhf45555hhfh"
    app.secret_key = os.urandom(16)
    app.run(debug=True)
