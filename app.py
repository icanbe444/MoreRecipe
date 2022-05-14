# from cgi import test
# from cgitb import text
# from email.mime import image
# from http.client import FORBIDDEN
# import os
# from crypt import methods
# from fileinput import filename
# from os import abort
# from turtle import update
# from urllib import response
# from wsgiref import headers
# from xml.dom.minidom import Identified
import email
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
from peewee import *
from datetime import date, datetime, timedelta
from flask import Flask, session, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import re
from model import *
from werkzeug.utils import secure_filename
import cloudinary
import cloudinary.uploader
from flask_mail import Mail, Message

Access_Token= "c8d45db64bc41de9e99793344c1bd78b53a500fe"
regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
UPLOAD_FOLDER = '/Users/user/PythonProject/MoreRecipe/uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'owoicanbe444sunkami_5#y2L"F4Q8z\n\xec]/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
jwt = JWTManager(app)
cloudinary.config(
    cloud_name="tpais",
    api_key="127237393369473",
    api_secret="-G9UJLTlf8PufwDpNo5xy4nLD_4"
)
#This is the config for my email sender - mailtrap
app.config['MAIL_SERVER']='smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = '6cce44c9b47764'
app.config['MAIL_PASSWORD'] = 'c6af206f893311'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)


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
        app.logger.info('in upload route')
        upload_result = None
    if 'file' not in request.files:
        resp = jsonify({'message': 'No file part in the request'})
        resp.status_code = 400
        return resp
    file = request.files['file']
    if file.filename == '':
        resp = jsonify({'message': 'No file selected for uploading'})
        resp.status_code = 400
        return resp
   
    if file and allowed_file(file.filename):
        upload_result = cloudinary.uploader.upload(file)
        
        fullname = request.form['fullname']
        username = request.form['username']
        email = request.form['email']
        password_harsh = request.form['password']
        birthday = request.form['birthday']
        gender = request.form['gender']
        if not fullname:
            return jsonify({'message':'Missing Name'})
        if not username:
            return jsonify({'message':'Missing username'})
        if not password_harsh:
            return jsonify({'message':'Missing password'})
        if not email:
            return jsonify({'message':'Missing email'})
        if not re.fullmatch(regex, email):
            return jsonify({'message':'Please enter a vilid email'})
        
        registered_user = Users.select().where(Users.email == email)
        check_username = Users.select().where(Users.username == username)
        if registered_user:
            return jsonify({'message':'User Already Exists'}), 400
        elif check_username:
                return jsonify({'message':'Username Taken'}), 400
        else:
            url = upload_result["secure_url"]
            hashed_pw = generate_password_hash(password_harsh, "sha256")
            user = Users.create(fullname=fullname, username=username, email=email,
                                password_harsh=hashed_pw, birthday=birthday, gender=gender, profile = url)
            msg = Message('Welcome to your recipe world!', sender =   'icanbe444@gmail.com', recipients = [email])
            msg.body = f"Hey {username}, sending you this email from my Flask app, lmk if it works"
            mail.send(msg)
            return jsonify({'Status': f'Dear {username}, Your registration is successful', 
                            'Message':'Please check your mail for further instructions',}), 200
        

    return jsonify({'message': 'Please enter your detail'}), 400
   


@app.route('/profile', methods=['GET'])
@jwt_required()
def profile_page():

    current_user = get_jwt_identity()
    users = Users.select(Users.username, Users.fullname,
                         Users.gender, Users.email, Users.birthday, Users.id).where(Users.id == current_user)
    output = [user for user in users.dicts()]
    return jsonify({'logged_in_as': output}), 200

    


@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
    
        username = request.form['username']
        password = request.form['password']
        
        if not username:
            return jsonify({'message':'Missing username'}), 400
    
        if not password:
            return jsonify({'message': 'Missing password'}), 400
        
        try:
            registered_user = Users.get(Users.username == username)
        except DoesNotExist:
            return jsonify({'message':'Invalid Login Info'}), 400
            
        password_pass = check_password_hash(registered_user.password_harsh, password)
    
        if password_pass:
            access_token = create_access_token(identity=registered_user)
            return {"access_token": access_token}, 200
        return jsonify({'message':"Password incorrect"}), 400

    return jsonify({'message':"Please provide an email and password"}), 400


@app.route('/request_password_reset', methods=['POST'])
def request_password_reset():
    if request.method == 'POST':
        email = request.form['email']
        if not email:
            return jsonify({'message':'Missing email'})
        if not re.fullmatch(regex, email):
            return jsonify('Please enter a vilid email')
    registered_user = Users.select(Users.email).where(Users.email == email).count()
    if not registered_user:
        return jsonify({'message':"Account doesn't exit"}), 400
    msg = Message('Reset Password', sender =   'icanbe444@gmail.com', recipients = [email])
    msg.body = "Hey, You have requested a password reset"
    mail.send(msg)
    return jsonify({'Message':'Please check your mail for further instructions',}), 200
                        

@app.route('/reset_password/<email>', methods=['PATCH'])
def reset_password(email):
    if request.method == 'PATCH':
        password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        registered_user = Users.get(Users.email == email)
        password_pass = check_password_hash(
                registered_user.password_harsh, password)
        print(type(registered_user))
        if registered_user:
            
            if password_pass:
                if new_password != confirm_password:
                    return jsonify({'message':'Password do not match'})
                hashed_pw = generate_password_hash(new_password, "sha256")
                update_password = Users.update(password_harsh=hashed_pw).where(Users.email == email)
                update_password.execute()
                msg = Message('Reset Password Successful', sender =   'icanbe444@gmail.com', recipients = [email])
                msg.body = "Hey, Your password has been successfully changed"
                mail.send(msg)
                return jsonify({'Message':'Please check your mail for further instructions',}), 200
                
        return jsonify({'message':'Invalid details'}), 400
    return jsonify({'message':'Enter your details'}), 400
    
    

@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    users = Users.select(Users.username, Users.fullname,
                         Users.gender, Users.email, Users.birthday, Users.id)
    output = [user for user in users.dicts()]
    return jsonify({'App_Users': output})


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
@app.route('/add_recipe', methods=['POST'])
@jwt_required()
def add_recipe():
    current_user = get_jwt_identity()
    app.logger.info('in upload route')
    upload_result = None
    if 'file' not in request.files:
        resp = jsonify({'message': 'No file part in the request'})
        resp.status_code = 400
        return resp
    file = request.files['file']
    if file.filename == '':
        resp = jsonify({'message': 'No file selected for uploading'})
        resp.status_code = 400
        return resp
   
    if file and allowed_file(file.filename):
        upload_result = cloudinary.uploader.upload(file)
        name = request.form['name']
        description = request.form['description']
        ingredients = request.form['ingredients']
        process = request.form['process']
        poster_id = current_user
        url = upload_result["secure_url"]
        new_recipe = Recipe.create(name=name, description=description, ingredients=ingredients,
                                   process=process, poster_id=poster_id, image= url)
        return jsonify({'Status': 'Success', 'Message':'Recipe successfully added', 'RecipeName': name})
       


@app.route('/recipes', methods=['GET'])
def get_all_recipes():
    recipes = Recipe.select(Recipe.name, Recipe.description, Recipe.ingredients,
                            Recipe.process, Recipe.poster_id, Recipe.id, Recipe.post_date, 
                            Recipe.image).order_by(Recipe.post_date.desc())
    output = [recipe for recipe in recipes.dicts()]
    return jsonify(output)

@app.route('/recipe/<int:id>', methods=['GET'])
@jwt_required()
def get_one_recipe(id):
    current_user = get_jwt_identity()
    # query = Recipe.select().where((Recipe.poster_id == current_user) & (Recipe.id == id))
    
    if not Recipe.select().where(Recipe.id == id).exists():
        return 'Recipe ID does not Exist', 404
    recipe = Recipe.select(Recipe.name, Recipe.description, Recipe.ingredients,
                            Recipe.process, Recipe.poster_id, Recipe.id, Recipe.post_date, 
                            Recipe.image).join(Users).where(Recipe.id == id)
    
    output = [recipe for recipe in recipe.dicts()]
    return jsonify(output)

@app.route('/recipes/<int:page>', methods=['GET'])
def get_recipe_page(page=1):
    if request.method == 'GET':
        per_page = 2
        query = Recipe.select()
    recipes = Recipe.select(Recipe.name, Recipe.description, Recipe.ingredients,
                            Recipe.process, Recipe.poster_id, Recipe.id, Recipe.post_date, 
                            Recipe.image).order_by(Recipe.post_date.desc()).paginate(page, per_page)
    output = [recipe for recipe in recipes.dicts()]
    return jsonify(output)   


@app.route('/my_recipes/<int:page>', methods=['GET'])
@jwt_required()
def get_my_recipes(page=1):
    per_page = 2
    current_user = get_jwt_identity()
    recipes = Recipe.select(Recipe.name, Recipe.description, Recipe.ingredients,
                            Recipe.process, Recipe.poster_id, Recipe.id, Recipe.post_date, 
                            Recipe.image).join(Users).where(Recipe.poster_id == current_user).order_by(
                                Recipe.post_date.desc()).paginate(page, per_page)
    output = [recipe for recipe in recipes.dicts()]
    return jsonify(output)


@app.route('/recipes_likes/<int:id>', methods=['GET'])
@jwt_required()
def recipes_likes(id):
    current_user = get_jwt_identity()
    
    recipes = Like.select(Like.poster_id, Like.post_date).join(Recipe).where(Recipe.id == id).order_by(Recipe.post_date.desc())

    output = [recipe for recipe in recipes.dicts()]
    return jsonify(output)

@app.route('/recipes_dislikes/<int:id>', methods=['GET'])
@jwt_required()
def recipes_dislikes(id):
    current_user = get_jwt_identity()
    
    recipes = Dislike.select(Dislike.poster_id, Dislike.post_date).join(Recipe).where(Recipe.id == id).order_by(Recipe.post_date.desc())

    output = [recipe for recipe in recipes.dicts()]
    return jsonify(output)


@app.route('/recipes_comments/<int:id>', methods=['GET'])
@jwt_required()
def recipes_comments(id):
    current_user = get_jwt_identity()
    
    recipes = Comment.select(Comment.poster_id, Comment.post_date, 
    Comment.text).join(Recipe).where(Recipe.id == id).order_by(Recipe.post_date.desc())

    output = [recipe for recipe in recipes.dicts()]
    return jsonify(output)




@app.route('/delete/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_recipe(id):
    current_user = get_jwt_identity()
    if not Recipe.select().where(Recipe.id == id).exists():
        return jsonify({'message':'Recipe ID does not Exist'}), 404
    if not Recipe.select().where((Recipe.poster_id == current_user) & (Recipe.id == id)):
            return jsonify({'message':'You are not autorized to change this recipe'}), 403
    delete_recipe = Recipe.delete().where(Recipe.id == id)
    data = delete_recipe.execute()
    return jsonify({'status': data, 'message': 'Recipe successfully deleted'})
    



@app.route('/update/<int:id>', methods=['PUT'])
@jwt_required()
def update_recipe(id):
    current_user = get_jwt_identity()
    app.logger.info('in upload route')
    upload_result = None
    if 'file' not in request.files:
        resp = jsonify({'message': 'No file part in the request'})
        resp.status_code = 400
        return resp
    file = request.files['file']
    if file.filename == '':
        resp = jsonify({'message': 'No file selected for uploading'})
        resp.status_code = 400
        return resp
   
    if file and allowed_file(file.filename):
        upload_result = cloudinary.uploader.upload(file)
        name = request.form['name']
        description = request.form['description']
        ingredients = request.form['ingredients']
        process = request.form['process']
        poster_id = current_user
        url = upload_result["secure_url"]
        query = Recipe.select().where((Recipe.poster_id == current_user) & (Recipe.id == id))
        if not Recipe.select().where(Recipe.id == id).exists():
            return jsonify({'Status':'Unsuccessful', 'Message': 'Recipe ID does not Exist'}), 404
        if not query:
            return jsonify({'Status': 'Unseccessful', 'Message':'You are not autorized to change this recipe'}), 403
        update_recipe = Recipe.update(name=name, description=description, ingredients=ingredients, process=process,
                                      poster_id=poster_id, image= url).where((Recipe.poster_id == current_user) & (Recipe.id == id))
        update_recipe.execute()
        return jsonify({'Status': 'Success', 'Message':'Recipe successfully updated', 'RecipeName': name})    
    else:
        resp = jsonify({'message': 'Allowed file types are txt, pdf, png, jpg, jpeg, gif'}), 400
        return resp
    

@app.route("/search", methods=['GET'])
def get_search():
    my_search = request.args.get('querry')
    search_results = Recipe.select().where(Recipe.name ** (f'%{my_search}%')).order_by(Recipe.post_date.desc())
    output = [recipe for recipe in search_results.dicts()]
    if not output:
        return jsonify({'SearchResult': 'Your search did not match any recipe'})

    else:
        return jsonify(output)
    
   
    
@app.route("/comment/<int:id>", methods=['POST'])   
@jwt_required()
def create_comment(id):
    current_user = get_jwt_identity()
    comment = request.form['comment']
    if not Recipe.select().where(Recipe.id == id).exists():
        return jsonify({'Status': 'Unsuccessful', 'Message': 'Recipe ID does not Exist'}), 400
    if not comment:
        return jsonify({'Status': 'Character Error', 'Message': 'Comment session cannot be empty'}), 400
    if len(comment) > 10:
        return jsonify({'Status': 'Input Error', 'Message': 'You have exceeded the number of character'}), 400
    
    recipe_id = Recipe.get(id)
    new_comment = Comment.create(recipe_id = recipe_id ,text=comment, poster_id=current_user )
    return jsonify({'Status': 'Successful', 'Message':'Comment successfully posted', 'Comment': comment}), 201



@app.route("/like/<int:id>", methods=['GET'])
@jwt_required()
def like(id):
    current_user = get_jwt_identity()
    if not Recipe.select().where(Recipe.id == id).exists():
        return jsonify({'Status': 'Unsuccessful', 'Message': 'Recipe ID does not Exist'}), 400
    like = Like.select().where((Like.poster_id == current_user))
    if like:
        like = Like.delete().where((Like.poster_id == current_user))
        data = like.execute()
        return jsonify({'status': data, 'message': 'Recipe like deleted'})
    else: 
        new_like = Like.create(recipe_id = id , poster_id=current_user )
        return jsonify({'Status': 'Successful', 'Message': 'You have liked a recipe'}), 200

    
@app.route("/dislike/<int:id>", methods=['GET'])
@jwt_required()
def dislike(id):
    current_user = get_jwt_identity()
    if not Recipe.select().where(Recipe.id == id).exists():
        return jsonify({'Status': 'Unsuccessful', 'Message': 'Recipe ID does not Exist'}), 400
    dislike = Dislike.select().where(Dislike.recipe_id == id)
    like = Like.select().where(Like.poster_id == current_user)
    if like:
        like = Like.delete().where(Like.poster_id == current_user)
        return jsonify({'Status': 'Successful', 'result': like.execute(), 'Message': 'Like Deleted'}), 204
    elif dislike:
        remove_dislike = Dislike.delete()
        data = remove_dislike.execute()
        return jsonify({'status': data, 'message': 'Recipe dislike deleted'})
    else:
        create_dislike = Dislike.create(recipe_id =id , poster_id=current_user )     
        return jsonify({'Status': 'Successful', 'Message': 'Recipe has been disliked'}), 200




@app.route('/update_user/<username>', methods=['PATCH'])
@jwt_required()
def update_user(username):
    current_user = get_jwt_identity()
    if request.method == 'PATCH':
        app.logger.info('in upload route')
        upload_result = None
    if 'file' not in request.files:
        resp = jsonify({'message': 'No file part in the request'})
        resp.status_code = 400
        return resp
    file = request.files['file']
    if file.filename == '':
        resp = jsonify({'message': 'No file selected for uploading'})
        resp.status_code = 400
        return resp
   
    if file and allowed_file(file.filename):
        upload_result = cloudinary.uploader.upload(file)
        fullname = request.form['fullname']
        birthday = request.form['birthday']
        gender = request.form['gender']
        url = upload_result["secure_url"]
        query = Users.select().where(Users.username == username)
        email = [users.email for users in query]
        use_email = query[0].email
        update_user = Users.update(fullname = fullname, birthday = birthday, gender= gender,profile = url).where(Users.username == username)
        update_user.execute()
        msg = Message('Update Successful', sender =   'icanbe444@gmail.com', recipients = [use_email])
        msg.body = f"Hey {username}, Your profile has been successfully updated"
        mail.send(msg)
        return jsonify({'Message':'Your profile has been updated'}), 200
                        
    return jsonify({'message':'Invalid details'}), 400










if __name__ == '__main__':
    app.run(debug=True)

            
            