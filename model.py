from enum import unique
import mimetypes
from tkinter.tix import Tree
from unicodedata import name
from peewee import *
from datetime import date
from flask import Flask, session, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

# db = SqliteDatabase('more_recipe.db')

db = MySQLDatabase('more_recipe',  user='root', password='Sunk@nmi84!@',host='localhost', port=3306)
app = Flask(__name__)


class BaseModel(Model):
    class Meta:
        database = db
        
class Users(BaseModel):
    id = PrimaryKeyField(primary_key=True)
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
    id = PrimaryKeyField(primary_key=True)
    name = CharField()
    description = CharField()
    ingredients = CharField()
    process = TextField()
    post_date = DateTimeField(constraints=[SQL('DEFAULT CURRENT_TIMESTAMP')])
    poster_id = ForeignKeyField(Users, backref='recipe', lazy_load=False)
    image = CharField()


class Comment(BaseModel):
    id = PrimaryKeyField(primary_key=True)
    text = CharField()
    recipe_id = ForeignKeyField(Recipe, backref='comment', lazy_load=False)
    post_date = DateTimeField(constraints=[SQL('DEFAULT CURRENT_TIMESTAMP')])
    poster_id = ForeignKeyField(Users, backref='comment', lazy_load=False)
    


class Like(BaseModel):
    id = PrimaryKeyField(primary_key=True)
    recipe_id = ForeignKeyField(Recipe, backref='comment', lazy_load=False)
    post_date = DateTimeField(constraints=[SQL('DEFAULT CURRENT_TIMESTAMP')])
    poster_id = ForeignKeyField(Users, backref='like', lazy_load=False)
    
 

class Dislike(BaseModel):
    id = PrimaryKeyField(primary_key=True)
    recipe_id = ForeignKeyField(Recipe, backref='comment', lazy_load=False)
    post_date = DateTimeField(constraints=[SQL('DEFAULT CURRENT_TIMESTAMP')])
    poster_id = ForeignKeyField(Users, backref='dislike', lazy_load=False)
    

  

def initialize_db():
    db.connect()
    db.create_tables([Users, Recipe, Like, Dislike, Comment])

