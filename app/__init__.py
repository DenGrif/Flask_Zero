from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

# Создаём объект Flask:
app = Flask(__name__)

# 4. Устанавливаем секретный ключ:
app.config['SECRET_KEY'] = 'your_secret_key'

# 5. Настраиваем базу данных:
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

# 6. Создаём объект SQLAlchemy:
db = SQLAlchemy(app)

# 7. Создаём объект Bcrypt:
bcrypt = Bcrypt(app)

# 8. Создаём объект LoginManager:
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Модуль будет перенаправлять пользователя на маршрут, который мы указываем (на авторизацию)

# 9. Импортируем маршрут (файл из пакета):
from app import routes