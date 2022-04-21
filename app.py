from cgi import test
import os
from crypt import methods
from fileinput import filename
from os import abort
from turtle import update
from urllib import response
from xml.dom.minidom import Identified
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
from peewee import *
from datetime import date, datetime, timedelta
from flask import Flask, session, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import re
from model import *
from werkzeug.utils import secure_filename


UPLOAD_FOLDER = '/Users/user/PythonProject/MoreRecipe/uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'owoicanbe444sunkami_5#y2L"F4Q8z\n\xec]/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
jwt = JWTManager(app)
# DB setup using MYSQLAlchemy
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymsql://root:Sunk@nmi84!@@localhost/more_recipe'


@app.before_request
def _db_connect():
    db.connect()

# This hook ensures that the connection is closed when we've finished
# processing the request.


@app.teardown_request
def _db_close(exc):
    if not db.is_closed():
        db.close()


@jwt.user_identity_loader
def user_identity_lookup(Users):
    return Users.id


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return Users.get(id=identity)


@app.route('/register', methods=['POST', 'GET'])
def register():

    if request.method == 'POST':
        fullname = request.form['fullname']
        username = request.form['username']
        email = request.form['email']
        password_harsh = request.form['password']
        birthday = request.form['birthday']
        gender = request.form['gender']
        if not fullname:
            return jsonify('Missing Name')
        if not username:
            return jsonify('Missing username')
        if not password_harsh:
            return jsonify('Missing password')
        if not email:
            return jsonify('Missing email')
        registered_user = Users.select(Users.username).where(
            Users.username == username).count()
        if registered_user:
            return jsonify('User Already Exists'), 400
        hashed_pw = generate_password_hash(password_harsh, "sha256")
        user = Users.create(fullname=fullname, username=username, email=email,
                            password_harsh=hashed_pw, birthday=birthday, gender=gender)

        return {"You have been registered"}, 200

    return jsonify('Please enter your detail'), 400


@app.route('/profile', methods=['GET'])
@jwt_required()
def profile_page():

    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']
        if not username:
            return jsonify('Missing username'), 400

        if not password:
            return jsonify('Missing password'), 400
        registered_user = Users.get(
            Users.username == username, Users.fullname == Users.fullname)
        password_pass = check_password_hash(
            registered_user.password_harsh, password)
        if registered_user:

            if password_pass:
                access_token = create_access_token(identity=registered_user)
                return {"access_token": access_token}, 200

        else:
            return jsonify('Invalid Login Info'), 400

    return jsonify("Please provide an email and password"), 400


@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    users = Users.select(Users.username, Users.fullname,
                         Users.gender, Users.email, Users.birthday, Users.id)
    output = [user for user in users.dicts()]
    return jsonify(output)


@app.route('/recipes', methods=['GET'])
def get_all_recipes():

    recipes = Recipe.select(Recipe.name, Recipe.description, Recipe.ingredients,
                            Recipe.process, Recipe.poster_id, Recipe.id, Recipe.post_date)
    output = [recipe for recipe in recipes.dicts()]
    return jsonify(output)


@app.route('/my_recipes', methods=['GET'])
@jwt_required()
def get_my_recipes():
    current_user = get_jwt_identity()

    query = Recipe.select().join(Users).where(Recipe.poster_id == current_user)
    recipes = []
    for recipe in query:
        recipe_data = {'Recipe ID': recipe.id}
        recipes.append(recipe_data)
    return jsonify(recipes)


@app.route('/delete/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_recipe(id):
    current_user = get_jwt_identity()
    query = Recipe.delete().where((Recipe.poster_id == current_user) & (Recipe.id == id))
    return jsonify({'result': query.execute()}), 204


@app.route('/update/<int:id>', methods=['PUT'])
@jwt_required()
def update_recipe(id):
    current_user = get_jwt_identity()

    # return jsonify({'result': query.execute()})

    if not request.method == 'PUT':

        return jsonify('Please enter your data')

    else:
        name = request.form['name']
        description = request.form['description']
        ingredients = request.form['ingredients']
        process = request.form['process']
        poster_id = current_user
        if not name:
            return jsonify('Missing Name')
        if not description:
            return jsonify('Missing description')
        if not ingredients:
            return jsonify('Missing ingredients')
        if not process:
            return jsonify('Missing process')
        update_recipe = Recipe.update(name=name, description=description, ingredients=ingredients, process=process,
                                      poster_id=poster_id).where((Recipe.poster_id == current_user) & (Recipe.id == id))

        return jsonify({'result': update_recipe.execute()}), 201


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/add_recipe', methods=['POST'])
@jwt_required()
def add_recipe():
    
    if 'file' not in request.files:
        resp = jsonify({'message': 'No file part in the request'})
        resp.status_code = 400
        return resp
    file = request.files['file']
    if file.filename == '':
        resp = jsonify({'message': 'No file selected for uploading'})
        resp.status_code = 400
        return resp
    current_user = get_jwt_identity()
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        name = request.form['name']
        description = request.form['description']
        ingredients = request.form['ingredients']
        process = request.form['process']
        poster_id = current_user
        image_path = app.config['UPLOAD_FOLDER']+ '/' + filename
        new_recipe = Recipe.create(name=name, description=description, ingredients=ingredients,
                                   process=process, poster_id=poster_id, image=image_path)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        resp = jsonify({'message': 'File successfully uploaded'})
        resp.status_code = 201
        return resp
    else:
        resp = jsonify(
            {'message': 'Allowed file types are txt, pdf, png, jpg, jpeg, gif'})
        resp.status_code = 400
        return resp


if __name__ == '__main__':
    app.run(debug=True)
