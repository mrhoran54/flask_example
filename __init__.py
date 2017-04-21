from flask import Flask

app = Flask(__name__)
app.config.from_object('config')
# db = SQLAlchemy(app)
app.config.update(
    DEBUG = True,
)


from app import views # models
