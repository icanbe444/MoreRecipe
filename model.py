from tkinter.tix import Tree
from peewee import *
from datetime import date
from flask import Flask, session, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

db = SqliteDatabase('more_recipe.db')
app = Flask(__name__)

class Users(Model):
    full_name = CharField()
    user_name = CharField()
    email = CharField()
    password_harsh = CharField()
    birthday = DateField()
    gender = CharField()

    class Meta:
        database = db
    @property
    def password(self):
        raise AttributeError('Password is not readabale attribure!')

    @password.setter
    def password(self, password):
        self.password_harsh = generate_password_hash(password)

    def verify_password(self,password):
        return check_password_hash(self.password_harsh, password)



class Recipe(Model):
   
    name = CharField()
    description = CharField()
    ingredients = CharField()
    process = CharField()

    class Meta:
        database = db # this model uses the "more_recipe.db" database

   


def initialize_db():
    db.connect()
    db.create_tables([Users, Recipe], safe=True)

