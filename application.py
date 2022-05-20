from flask import Flask, redirect, url_for, render_template, session, request, flash
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
import requests
import json
# import spoonacular
# from spoonacular.exceptions import ApiException

# def say_hello(username = "World"):
#     return '<p>Hello %s</p>\n' % username

# header_text = '''
#     <html>\n<head> <title>EB Flask Test</title> </head>\n<body>'''
# instructions = '''
#     <p><em>Hint</em>: This is a RESTful web service! Append a username
#     to the URL (for example: <code>/Thelonious</code>) to say hello to
#     someone specific.</p>\n'''
# home_link = '<p><a href="/">Back</a></p>\n'
# footer_text = '</body>\n</html>'

application = Flask(__name__)
application.secret_key = 'SECRET_KEY'


# application.add_url_rule('/', 'index', (lambda: header_text +
#     say_hello() + instructions + footer_text))

# application.add_url_rule('/<username>', 'hello', (lambda username:
#     header_text + say_hello(username) + home_link + footer_text))

@application.route("/")
def index():
    return render_template("landing.html")

@application.route("/login", methods = ['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('library'))
    
    if request.method == 'POST':
        if validate_password(request.form['username'], request.form['password']):
            session['username'] = request.form['username']
            user = get_user(request.form['username'])
            session['first_name'] = user['first_name']
            flash('Login successful')
            return redirect(url_for('library'))
        flash('Username or password is incorrect.')
    return render_template("login.html")


@application.route("/register", methods = ['GET', 'POST'])
def register():
    if 'username' in session:
        session.pop('username', None)
        session.pop('name', None)
    
    if request.method == 'POST':
        if validate_username(request.form['username']):
            flash('Username is already in use.')
            return render_template('register.html')
        
        create_user(request.form['username'], request.form['first_name'], request.form['password'])
        flash('Account created successfully.')
        return redirect(url_for('login'))
    return render_template("register.html")


@application.route("/library", methods = ['GET', 'POST'])
def library():
    if 'username' not in session:
        flash('Please login.')
        return redirect(url_for('login'))
    
    if 'recipe_id' in request.args:
        recipe_id = request.args['recipe_id']
        username = session['username']
        if request.args['action'] == 'remove':
            remove_collection_item(username, recipe_id)
        return redirect(url_for('library'))

    collection = get_collection_recipes(session['username'])
    return render_template("library.html", collection=collection)


@application.route("/logout")
def logout():
    session.pop('username', None)
    session.pop('first_name', None)
    flash('Logged out.')
    return redirect(url_for('login'))


@application.route('/recipe/<recipe_id>', methods = ['GET', 'POST'])
def recipe(recipe_id):
    if 'username' not in session:
        flash('Please login.')
        return redirect(url_for('login'))

    try:
        recipe = get_recipe_details(recipe_id)
        add = not recipe_in_collection(session['username'], recipe_id)
    except Exception as e:
        flash("Recipe not found.")
        return redirect(url_for('search'))
    return render_template("recipe.html", recipe=recipe, add=add)

@application.route('/recipe')
@application.route('/recipe/')
def no_recipe():
    if request.args['recipe_id'] is not None:
        recipe_id = request.args['recipe_id']
        username = session['username']
        if request.args['action'] == 'add':
            add_collection_item(username, recipe_id)
        if request.args['action'] == 'remove':
            remove_collection_item(username, recipe_id)
        redirect_url = recipe_id
        return redirect(redirect_url)

    return redirect(url_for('search'))



@application.route("/search")
def search():
    if 'username' not in session:
        flash('Please login.')
        return redirect(url_for('login'))
    
    if request.method == 'GET' and 'query' in request.args:
        recipes = search_recipes(request.args['query'])
        if len(recipes) == 0:
            flash("No recipes found. Try again.")
        return render_template("search.html", recipes=recipes, query=request.args['query'])
    
    if request.method == 'POST':
        comment = 'comment'
    
    return render_template("search.html")


# AUXILIARY METHODS
# db_client = boto3.client('dynamodb', region_name='us-east-1')

# ### Test method -- DELETE later
# def get_items():
#     return db_client.scan(
#         TableName='login'
#     )

dynamodb = boto3.resource('dynamodb', 
    region_name='us-east-1',
    aws_access_key_id='AKIASVFBNRFKCY25MV6C',
    aws_secret_access_key='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')


# configuration = spoonacular.Configuration()
# configuration.api_key['apiKey'] = 'a2140860553b4e348b1070aabb09183a'
# api_instance = spoonacular.IngredientsAPI(spoonacular.ApiClient(configuration))


def validate_username(username):
    for user in get_users():
        if username == user['username']:
            return True
    return False

def validate_password(username, password):
    for user in get_users():
        if username == user['username'] and password == user['password']:
            return True
    return False

def get_users():
    table = dynamodb.Table('login')
    scan_kwargs = {
        'ProjectionExpression': 'username, first_name, password'
    }
    done = False
    start_key = None
    while not done:
        if start_key:
            scan_kwargs['ExclusiveStartKey'] = start_key
        response = table.scan(**scan_kwargs)
        done = start_key is None
    return(response['Items'])

def get_user(username):
    for user in get_users():
        if username == user['username']:
            return user

def create_user(username, first_name, password):
    table = dynamodb.Table('login')
    response = table.put_item(
        Item={
            'username': username,
            'first_name': first_name,
            'password': password
        }
    )
    return response

def get_collection_items(username):
    table = dynamodb.Table('collection')
    response = table.query(
        KeyConditionExpression=Key('user_id').eq(username)
    )
    return response['Items']

def get_collection_recipes(username):
    recipes = []
    # table = dynamodb.Table('recipe')
    for item in get_collection_items(username):
        recipe = get_recipe_details(item['recipe_id'])
        recipes.append(recipe)
        # response = table.query(
        #     KeyConditionExpression=Key('id').eq(item['recipe_id'])
        # )
        # recipes.append(response['Items'])
    return recipes

def remove_collection_item(username, recipe_id):
    table = dynamodb.Table('collection')
    try:
        response = table.delete_item(
            Key={
                'user_id': username,
                'recipe_id': recipe_id
            }
        )
    except ClientError as e:
        return e.response['Error']['Message']
    else:
        return response

def add_collection_item(username, recipe_id):
    table = dynamodb.Table('collection')
    response = table.put_item(
        Item={
            'user_id': username,
            'recipe_id': recipe_id
        }
    )
    return response

def get_recipe_details(recipe_id):
    query_url = "https://api.spoonacular.com/recipes/"+recipe_id+"/information"
    parameters = {
        'apiKey': 'a2140860553b4e348b1070aabb09183a'
    }
    response = requests.get(query_url, params=parameters)
    return response.json()

def search_recipes(query_string):
    query_url = "https://api.spoonacular.com/recipes/complexSearch"

    query_strip = query_string.strip()
    query = query_strip.replace(" ", "")
    query = "\'"+query+"\'"

    parameters = {
        'apiKey': 'a2140860553b4e348b1070aabb09183a',
        'query': query,
        'number': 100
    }
    response = requests.get(query_url, params=parameters)
    return response.json()['results']

def recipe_in_collection(username, recipe_id):
    for item in get_collection_items(username):
        if item['recipe_id'] == recipe_id:
            return True
    return False


# run the application.
if __name__ == "__main__":
    # Setting debug to True enables debug output. This line should be
    # removed before deploying a production application.
    application.debug = True
    application.run()