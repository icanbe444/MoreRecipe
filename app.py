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


@app.before_request
def before_request():
    initialize_db()

@app.after_request
def after_request(exception):
    db.close()

@app.route('/home')
def index():
    return 'You are not logged in'

@app.route('/register', methods=['POST', 'GET'])
def register():

    if request.method == 'POST':
        full_name = request.form['full_name']
        user_name = request.form['user_name']
        email = request.form['email']
        password_harsh = request.form['password']
        birthday = request.form['birthday']
        gender = request.form['gender']
        if not user_name:
            return jsonify('Missing user_name')
        if not password_harsh:
            return jsonify('Missing password')
        if not email:
            return jsonify('Missing email')
        registered_user = Users.select(Users.user_name).where(Users.user_name == user_name ).count()
        if registered_user:
            return jsonify('User Already Exists'), 400  
        hashed_pw = generate_password_hash(password_harsh, "sha256")
        user= Users.create(full_name = full_name,user_name=user_name, email=email, password_harsh= hashed_pw,birthday=birthday,gender=gender)
        access_token = create_access_token(identity={'user_name':user_name})
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
        
            user_name = request.form['user_name']
            password = request.form['password']
            if not user_name:
                return jsonify('Mission username'), 400

            if not password:
                return jsonify('Missing password'), 400
            registered_user = Users.get(Users.user_name == user_name)
            password_pass =  check_password_hash(registered_user.password_harsh, password)  
            if registered_user:     
                
                if password_pass:
                    access_token = create_access_token(identity={'user_name':user_name})
                    return {"access_token": access_token} , 200
                    
            
            else: 
                return jsonify('Invalid Login Info'), 400
        
        
   return jsonify("Please provide an email and password"), 400       
    
        

@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    users = Users.select(Users.user_name, Users.full_name, Users.gender)
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

    