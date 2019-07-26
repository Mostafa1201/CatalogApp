#!/usr/bin/env python
# Author : Mostafa Taher

from flask import Flask, render_template, request, redirect, url_for
from flask import jsonify, Response, abort, g, make_response, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from models import Base, Category, Item, User
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import random
import string
import requests
from functools import wraps

from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Menu Application"

engine = create_engine('sqlite:///catalogapp.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@auth.verify_password
def verify_password(username, password):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    print "Looking for user %s" % username
    user = session.query(User).filter_by(username=username).first()
    if not user:
        print "User not found"
        return False
    elif not user.verify_password(password):
        print "Unable to verify password"
        return False
    else:
        g.user = user
        return True


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' in login_session:
            return f(*args, **kwargs)
        else:
            flash("You are not allowed to access there")
            return redirect('/login')
    return decorated_function


@app.route('/regsiter', methods=['GET', 'POST'])
def register():
    """
    method/class name: register
    Args: none
    Returns:
        register user in system then redirect to login
    """
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        if(
            username is None or
            password is None or
            username == "" or
            password == ""
        ):
            print "missing arguments"
            abort(400)
        if(
            session.query(User).filter_by(username=username)
            .first() is not None
        ):
            print "existing user"
            user = session.query(User).filter_by(username=username).first()
            return jsonify({'message': 'user already exists'}), 200

        user = User(username=username, email=email)
        user.hash_password(password)
        session.add(user)
        session.commit()
        return redirect(url_for('login'))
    else:
        return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    method/class name: login
    Args: none
    Returns:
        login user in to the system then redirect to categories page
    """
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if(
            username is None or
            password is None or
            username == "" or password == ""
        ):
            print "missing arguments"
            abort(400)
        user = session.query(User).filter_by(username=username).first()
        if user is not None and verify_password(username, password):
            login_session['username'] = user.username
            login_session['email'] = user.email
            login_session['user_id'] = user.id
            return redirect(url_for('categories'))
        return redirect(url_for('login'))
    else:
        state = ''.join(
            random.choice(
                string.ascii_uppercase + string.digits
            ) for x in xrange(32)
        )
        login_session['state'] = state
        return render_template('login.html', STATE=state)


@app.route('/')
@app.route('/categories')
def categories():
    """
    method/class name: categoires
    Args: none
    Returns:
        get all the categories and the latest added items
    """
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    categories = session.query(Category).all()
    latestAddedItems = session.query(Item).limit(10).all()
    return render_template(
        'categories/index.html', categories=categories,
        latestAddedItems=latestAddedItems, login_session=login_session)


@app.route('/categories/new', methods=['GET', 'POST'])
@login_required
def newCategory():
    """
    method/class name: newCategory
    Args: none
    Returns:
        Add new Category
    """
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    if request.method == 'POST':
        if 'category' not in request.form:
            return """<script>function myFunction() {alert('Please fill
            the required inputs.');}</script>
            <body onload='myFunction()'>"""
        category_name = request.form['category']
        categoryCheck = session.query(
            Category).filter_by(name=category_name).first()
        if categoryCheck is None:
            newCategory = Category(
                name=request.form['category'],
                user_id=login_session['user_id']
            )
            session.add(newCategory)
            session.commit()
            return redirect(url_for('categories'))
        else:
            return redirect(url_for('categories'))
    else:
        return render_template('categories/create.html')


@app.route('/categories/<int:category_id>/edit', methods=['GET', 'POST'])
@login_required
def editCategory(category_id):
    """
    method/class name: editCategory
    Args:
        arg1 (data type: int): category_id
    Returns:
        edit category
    """
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    editedCategory = session.query(Category).filter_by(id=category_id).one()
    if login_session['user_id'] != editedCategory.user_id:
        return """<script>function myFunction() {alert('You are not authorized
        to add new categories to this catalog.');}</script>
        <body onload='myFunction()'>"""
    if request.method == 'POST':
        if 'name' not in request.form:
            return """<script>function myFunction() {alert('Please fill
            the required inputs.');}</script>
            <body onload='myFunction()'>"""
        editedCategory.name = request.form['name']
        session.add(editedCategory)
        session.commit()
        return redirect(url_for('categories'))
    else:
        return render_template(
            'categories/edit.html', category=editedCategory)


@app.route('/categories/<int:category_id>/delete', methods=['GET', 'POST'])
@login_required
def deleteCategory(category_id):
    """
    method/class name: deleteCategory
    Args:
        arg1 (data type: int): category_id
    Returns:
        register user in system then redirect to login
    """
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    categoryToDelete = session.query(Category).filter_by(id=category_id).one()
    if login_session['user_id'] != categoryToDelete.user_id:
        return """<script>function myFunction() {alert('You are not authorized
        to delete categories to this catalog.');}</script>
        <body onload='myFunction()'>"""
    categoryItemsToDelete = (
        session.query(Item)
        .filter_by(category_id=categoryToDelete.id).all()
    )
    if request.method == 'POST':
        session.delete(categoryToDelete)
        for item in categoryItemsToDelete:
            session.delete(item)
        session.commit()
        return redirect(url_for('categories'))
    else:
        return render_template(
            'categories/delete.html',
            category=categoryToDelete
        )


@app.route('/categories/<int:category_id>/items')
def CategoryItems(category_id):
    """
    method/class name: get Category Items
    Args:
        arg1 (data type: int): category_id
    Returns:
        get all items that belongs to a certain category
    """
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id)
    return render_template(
        'items/categoryItems.html', categories=categories, category=category,
        items=items, category_id=category_id, login_session=login_session)


@app.route('/items/new', methods=['GET', 'POST'])
@login_required
def newItem():
    """
    method/class name: newItem
    Args: none
    Returns:
        Add new Item to a category
    """
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    if request.method == 'POST':
        if 'title' not in request.form:
            return """<script>function myFunction() {alert('Please fill
            the required inputs.');}</script>
            <body onload='myFunction()'>"""
        item_title = request.form['title']
        itemCheck = session.query(
            Item).filter_by(title=item_title).first()
        if itemCheck is None:
            newItem = Item(
                title=request.form['title'],
                description=request.form['description'],
                category_id=request.form['category'],
                user_id=login_session['user_id']
            )
            session.add(newItem)
            session.commit()
            return redirect(
                url_for(
                    'CategoryItems',
                    category_id=newItem.category_id
                )
            )
        else:
            return redirect(
                url_for(
                    'CategoryItems',
                    category_id=request.form['category']
                )
            )
    else:
        categories = session.query(Category).all()
        return render_template('items/create.html', categories=categories)


@app.route('/items/<int:item_id>/edit',
           methods=['GET', 'POST'])
@login_required
def editItem(item_id):
    """
    method/class name: editItem
    Args:
        arg1 (data type: int): item_id
    Returns:
        Edit an item that belongs to a certain category
    """
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    editedItem = session.query(Item).filter_by(id=item_id).one_or_none()
    if editedItem is not None:
        if login_session['user_id'] != editedItem.user_id:
            return """<script>function myFunction() {alert('You are
            not authorized to edit items in this catalog.');}</script>
            <body onload='myFunction()'>"""
        if request.method == 'POST':
            if 'title' not in request.form:
                return """<script>function myFunction() {alert('Please fill
                the required inputs.');}</script>
                <body onload='myFunction()'>"""
            if request.form['title']:
                editedItem.title = request.form['title']
            if request.form['description']:
                editedItem.description = request.form['description']
            if request.form['category']:
                editedItem.category_id = request.form['category']
            session.add(editedItem)
            session.commit()
            return redirect(
                url_for(
                    'CategoryItems',
                    category_id=editedItem.category_id
                )
            )
        else:
            categories = session.query(Category).all()
            return render_template(
                'items/edit.html',
                categories=categories,
                item_id=item_id,
                item=editedItem
            )
    else:
        return """<script>function myFunction() {alert('The item you are
            trying to edit is not found.');}</script>
            <body onload='myFunction()'>"""


@app.route('/items/<int:item_id>')
def showItem(item_id):
    """
    method/class name: show Item
    Args:
        arg1 (data type: int): item_id
    Returns:
        Show an item that belongs to a certain category
    """
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    item = session.query(Item).filter_by(id=item_id).one()
    return render_template(
        'items/show.html',
        item=item,
        login_session=login_session
    )


@app.route('/items/<int:item_id>/delete',
           methods=['GET', 'POST'])
@login_required
def deleteItem(item_id):
    """
    method/class name: delete Item
    Args:
        arg1 (data type: int): item_id
    Returns:
        Delete an item that belongs to a certain category
    """
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    itemToDelete = session.query(Item).filter_by(id=item_id).one()
    if login_session['user_id'] != itemToDelete.user_id:
        return """<script>function myFunction() {alert('You are not authorized
        to delete items in this catalog.');}</script>
        <body onload='myFunction()'>"""
    category_id = itemToDelete.category_id
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        return redirect(url_for('CategoryItems', category_id=category_id))
    else:
        return render_template('items/delete.html', item=itemToDelete)


@app.route('/catalog/json')
def catalogJson():
    """
    method/class name: get Catalog Api as Json
    Args: none
    Returns:
        display a list of categories and their items as json
    """
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    categories = session.query(Category).all()
    response = []
    counter = 0
    for category in categories:
        categoryItems = (
            session.query(Item)
            .filter_by(category_id=category.id).all()
        )
        if(categoryItems is not None):
            items = []
            response.append(category.serialize)
            for item in categoryItems:
                items.append(item.serialize)
                response[counter]['items'] = items
        counter += 1
    return jsonify({'Categories': response})


def createUser(login_session):
    """
    method/class name: Create User
    Args:
        arg1 (data type: object): login_session
    Returns:
        Create User from the login session
    """
    newUser = User(
        username=login_session['username'],
        email=login_session['email']
    )
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """
    method/class name: get user info
    Args:
        arg1 (data type: int): user_id
    Returns:
        get user object by his/her id
    """
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    """
    method/class name: get User ID
    Args:
        arg1 (data type: str): email
    Returns:
        get user id by his/her email
    """
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Exception:
        return None


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """
    method/class name: Google Connect
    Args: none
    Returns:
        Login into google
    """
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'),
            200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/gdisconnect')
def gdisconnect():
    """
    method/class name: Google Disconnect
    Args: none
    Returns:
        Logout from google
    """
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.',
            400)
        )
        response.headers['Content-Type'] = 'application/json'
        return response

# Disconnect based on provider
@app.route('/logout')
def logout():
    """
    method/class name: Logout
    Args: none
    Returns:
        Logout and deleting all login data : (normal or google login data)
    """
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        del login_session['provider']
    else:
        flash("You were not logged in")
    del login_session['username']
    del login_session['email']
    del login_session['user_id']
    flash("You have successfully been logged out.")
    return redirect(url_for('categories'))


@app.route('/googleLogin')
def google_login():
    """
    method/class name: Google Login Page
    Args: none
    Returns:
        Show Google Login Page
    """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('googleLogin.html', STATE=state)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
