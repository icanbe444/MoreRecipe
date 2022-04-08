from enum import unique
from tkinter.tix import Tree
from peewee import *
from datetime import date
from flask import Flask, session, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

# db = SqliteDatabase('more_recipe.db')

db = MySQLDatabase('more_recipe',  user='root', password='Sunk@nmi84!@',host='localhost', port=3306)
app = Flask(__name__)


class BaseModel(Model):
    class Meta:
        database = db
class Users(BaseModel):
    id = IntegerField(primary_key=True)
    fullname = CharField()
    username = CharField()
    email = CharField()
    password_harsh = CharField()
    birthday = DateField()
    gender = CharField()

    
    @property
    def password(self):
        raise AttributeError('Password is not readabale attribure!')

    @password.setter
    def password(self, password):
        self.password_harsh = generate_password_hash(password)

    def verify_password(self,password):
        return check_password_hash(self.password_harsh, password)



class Recipe(BaseModel):
    id = IntegerField(primary_key=True)
    name = CharField()
    description = CharField()
    ingredients = CharField()
    process = TextField()
    post_date = DateTimeField(constraints=[SQL('DEFAULT CURRENT_TIMESTAMP')])
    poster = ForeignKeyField(Users, backref='recipe')

   
class Favorite(BaseModel):
    users = ForeignKeyField(Users, backref='favorites')
    recipe = ForeignKeyField(Recipe, backref='favorites')

def initialize_db():
    db.connect()
    db.create_tables([Users, Recipe, Favorite])

