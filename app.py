from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
from peewee import *
from datetime import date
from flask import Flask, session, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import re
from model import *





app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'owoicanbe444sunkami_5#y2L"F4Q8z\n\xec]/'
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

@app.route('/register', methods=['POST', 'GET'])
def register():

    if request.method == 'POST':
        fullname = request.form['fullname']
        username = request.form['username']
        email = request.form['email']
        password_harsh = request.form['password']
        birthday = request.form['birthday']
        gender = request.form['gender']
        if not username:
            return jsonify('Missing username')
        if not password_harsh:
            return jsonify('Missing password')
        if not email:
            return jsonify('Missing email')
        registered_user = Users.select(Users.username).where(Users.username == username ).count()
        if registered_user:
            return jsonify('User Already Exists'), 400  
        hashed_pw = generate_password_hash(password_harsh, "sha256")
        user= Users.create(fullname = fullname,username=username, email=email, password_harsh= hashed_pw,birthday=birthday,gender=gender)
        access_token = create_access_token(identity={'username':username})
        return {"access_token": access_token} , 200

    return jsonify('Please enter your detail'), 400  

    
    

@app.route('/profile', methods=['GET'])
@jwt_required()
def profile_page():
    
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200
  

@app.route('/login', methods=['POST'])
@jwt_required()
def login():
   if request.method == 'POST' :
        
            username = request.form['username']
            password = request.form['password']
            if not username:
                return jsonify('Mission username'), 400

            if not password:
                return jsonify('Missing password'), 400
            registered_user = Users.get(Users.username == username)
            password_pass =  check_password_hash(registered_user.password_harsh, password)  
            if registered_user:     
                
                if password_pass:
                    access_token = create_access_token(identity={'username':username})
                    return {"access_token": access_token} , 200
                    
            
            else: 
                return jsonify('Invalid Login Info'), 400
        
        
   return jsonify("Please provide an email and password"), 400       
    
        

@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    users = Users.select(Users.username, Users.fullname, Users.gender)
    output = [user for user in users.dicts()]
    return jsonify(output)
    



@app.route('/recipe', methods=['POST'])
@jwt_required()
def add_recipe():
    if  not request.method == 'POST':

        return jsonify('Please enter your data')

    else:
        name = request.form['name']
        description = request.form['description']
        ingredients = request.form['ingredients']
        process = request.form['process']

        new_recipe = Recipe.create(name = name, description = description, ingredients = ingredients, process=process)

    return jsonify("You have added new recipe")

@app.route('/recipes', methods=['GET'])
def get_all_recipes():
    recipes = Recipe.select(Recipe.name, Recipe.description, Recipe.ingredients, Recipe.process)
    output = [recipe for recipe in recipes.dicts()]
    return jsonify(output)
    


if __name__ == '__main__':
    app.run(debug=True)

    