# imported all required libaries for the project
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf.csrf import CSRFProtect
from flask_bootstrap import Bootstrap5
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.security import generate_password_hash, check_password_hash
from forms import UserForm, LoginForm, RegisterForm
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.environ.get('EMS_KEY')
csrf = CSRFProtect(app)
csrf.init_app(app)
Bootstrap5(app)

login_manager = LoginManager()
login_manager.init_app(app)


# create a database
class Base(DeclarativeBase):
    pass


app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get('DB_URI', "sqlite:///users.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# creating a user table in the database which holds id, username, email and password
class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(240), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

    # creating a relationship for users and records table
    records = db.relationship('Record', backref='user', lazy=True)


# creating a records table which holds energy, cost, date_posted, comments, user_id
class Record(db.Model):
    __tablename__ = 'records'

    id = db.Column(db.Integer, primary_key=True)
    energy = db.Column(db.Float, nullable=False)
    cost = db.Column(db.Float, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    comments = db.Column(db.String(240))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, user_id) or None


@app.route('/')
def index():
    return render_template('index.html')


# handels the login process for a user.
@app.route('/login', methods=['GET', 'POST'])
def get_logged_in():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        results = db.session.execute(db.select(User).where(User.email == email))
        user = results.scalar()

        if not user or not check_password_hash(user.password, password):
            flash("Please check if you entered have correct email or password.", "error")
            return redirect(url_for('get_logged_in'))
        else:
            login_user(user, remember=remember)
            return redirect(url_for('user_account'))
    return render_template('login.html', form=form, current_user=current_user)


# handels the sign up for a new user.
@app.route('/register', methods=['GET', 'POST'])
def get_registered():
    form = RegisterForm()
    if form.validate_on_submit():
        email = request.form.get('email')
        results = db.session.execute(db.select(User).where(User.email == email))
        user = results.scalar()
        if user:
            flash('Email has already been registered already. Please try logging in.', "error")
            return redirect(url_for('get_logged_in'))
        password = request.form.get('password')
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        new_user = User(
            name=request.form.get('name'),
            email=request.form.get('email'),
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Successful Registred, please login.', "success")
        return redirect(url_for('get_logged_in'))
    return render_template('register.html', form=form, current_user=current_user)


# handels the user input(create)
@app.route('/record', methods=['GET', 'POST'])
@login_required
def record():
    form = UserForm()
    if form.validate_on_submit():
        new_record = Record(
            energy=request.form.get('energy'),
            cost=request.form.get('cost'),
            comments=request.form.get('comments'),
            user_id=current_user.id
        )
        db.session.add(new_record)
        db.session.commit()
        flash('Successfully Recorded.', "success")
        return redirect(url_for('user_account'))
    return render_template('submit.html', form=form, current_user=current_user)


@app.route('/home')
def home():
    return render_template('home.html', current_user=current_user)


# handels the user profile page and records
@app.route('/profile')
@login_required
def user_account():
    page = request.args.get('page', 1, type=int)
    records_page = Record.query.filter_by(user_id=current_user.id).paginate(page=page, per_page=4)
    return render_template('account.html', name=current_user.name, records_page=records_page, current_user=current_user)


# handels the edit function for record
@app.route('/edit/<int:record_id>', methods=['GET', 'POST'])
@login_required
def edit_record(record_id):
    record_to_update = Record.query.get_or_404(record_id)
    edit_form = UserForm(
        energy=record_to_update.energy,
        cost=record_to_update.cost,
        comments=record_to_update.comments
    )
    if edit_form.validate_on_submit():
        record_to_update.energy = edit_form.energy.data
        record_to_update.cost = edit_form.cost.data
        record_to_update.comments = edit_form.comments.data
        db.session.commit()
        flash('Successfully updated.', "success")
        return redirect(url_for('user_account'))
    return render_template('edit.html', form=edit_form, is_edit=True, record=record_to_update)


# handles the delete function for record
@app.route('/delete/<int:record_id>')
@login_required
def delete_record(record_id):
    record_to_delete = Record.query.get_or_404(record_id)
    db.session.delete(record_to_delete)
    db.session.commit()
    flash('Successfully deleted.', "success")
    return redirect(url_for('user_account'))


@app.route('/logout')
def logout():
    logout_user()
    flash("You've been logged out.")
    return redirect(url_for('get_logged_in'))


if __name__ == '__main__':
    app.run(debug=False)
