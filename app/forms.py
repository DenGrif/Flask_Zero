# 1. Импортируем библиотеки:
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
# Валидатор EqualTo нужен для того, чтобы сравнивать значения в полях паролей и узнавать, точно ли они одинаковые.
# 2. Импортируем модель User из нашего модуля:
from app.models import User

# 3. Создаём класс RegistrationForm, который будет создавать форму:
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=35)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

# 4. Создаём функции для проверки уникальности имени пользователя и почты:
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Такое имя уже существует.')

    def validate_email(self, email):
        email = User.query.filter_by(email=email.data).first()
        if email:
            raise ValidationError('Такая почта уже используется.')

# 5. Создание класса LoginForm (для залогинившихся):
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Запомни меня')
    submit = SubmitField('Login')