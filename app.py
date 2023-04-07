from flask import Flask, request, render_template, url_for, redirect, make_response
from datetime import datetime, timedelta
import bcrypt
import jwt

app = Flask(__name__)

users = []
app.config['SECRET_KEY'] = 'mysecretkey'

@app.route("/", methods = ['GET', 'POST'])
def index():
    return redirect(url_for("login"))


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        repeat_password = request.form['repeat_password']
        if password == repeat_password:
            password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            new_user = {
                'name': name,
                'email': email,
                'password': password
            }
            users.append(new_user)
            print(users)
            return redirect(url_for('login'))
        return "Password did not match"
    return render_template('register.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        for user in users:
            print("USER ", user)
            if user['email'] == email:
                password = password.encode('utf-8')
                if bcrypt.checkpw(password, user['password']):
                    token_expiry = datetime.utcnow() + timedelta(minutes=1) # set token expiration time to 1 minute from now
                    token = jwt.encode({'email': email, 'exp': token_expiry}, app.config['SECRET_KEY'], algorithm='HS256')
                    resp = make_response(redirect(url_for('dashboard')))
                    resp.set_cookie('token', token)
                    return resp
    return render_template('login.html')

@app.route('/dashboard', methods=['POST', 'GET'])
def dashboard():
    token = request.cookies.get('token')
    print(token)
    if not token:
        return redirect(url_for('login'))

    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        # check if token is expired
        if datetime.utcnow() > datetime.fromtimestamp(data['exp']):
            return redirect(url_for('login'))
    except jwt.exceptions.ExpiredSignatureError:
        return redirect(url_for('login'))
    except jwt.exceptions.InvalidTokenError:
        return redirect(url_for('login'))

    # Only allow access to the dashboard for authenticated users
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)
