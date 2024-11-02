from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SubmitField, PasswordField, DecimalField, FloatField
from wtforms.validators import DataRequired

# created a user form to post in data
class UserForm(FlaskForm):
    energy = FloatField('Amount of Units:', validators=[DataRequired()])
    cost = FloatField('Cost of Units:', validators=[DataRequired()])
    comments = StringField('Note to self:')
    submit = SubmitField('Track me')

class LoginForm(FlaskForm):
    email = StringField('Email:', validators=[DataRequired()])
    password = PasswordField('Password:', validators=[DataRequired()])
    submit = SubmitField('Let me in')

class RegisterForm(FlaskForm):
    name = StringField('name', validators=[DataRequired()])
    email = StringField('email', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField('Add me up')