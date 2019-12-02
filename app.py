from flask import Flask, render_template, request, redirect
from flask import url_for, flash, session, abort
import subprocess 
from flask_wtf import CSRFProtect
import secrets
from passlib.hash import sha256_crypt
from flask_sqlalchemy import SQLAlchemy
import os
from datetime import datetime


app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(256)
csrf = CSRFProtect(app)

database_file = "sqlite:///" + os.path.join(os.getcwd(), "app.db")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_HTTPONLY = True,
    SQLALCHEMY_DATABASE_URI = database_file,
    SQLALCHEMY_TRACK_MODIFICATIONS = False
)

@app.after_request
def add_custom_headers(response):
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response


db = SQLAlchemy(app)

class QueryRecord(db.Model):
    __tablename__ = "query_records"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(30), nullable=False)
    query_text = db.Column(db.Text, nullable=False)
    query_results = db.Column(db.Text, nullable=False)

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(30), index=False, unique=True, nullable=False)
    password = db.Column(db.String(64), index=False, nullable=False)
    twofa = db.Column(db.String(11), index=False, nullable=False)

db.create_all()

def addUser(username, password, twofa):
    user = User(username=username, password=sha256_crypt.hash(password), twofa=twofa)
    db.session.add(user)  
    db.session.commit()

if((User.query.filter_by(username="admin").count()) == 0):
    addUser("admin", "Administrator@1", "12345678901")

def addQueryRecord(username, text, misspelled):
    query_record = QueryRecord(username=username, query_text=text, query_results=misspelled)
    db.session.add(query_record)  
    db.session.commit()


def isValidTwoFA(twofa):
    if not (10 <= len(twofa) <= 11):
        return False
    for char in twofa:
        if not char.isdigit():
            return False
    return True

def findMisspelled(text):
    spell_check_file_path = "./a.out"
    text_file_path = "./static/inputtext.txt"
    dict_file_path = "./static/wordlist.txt"
    textfile = open(text_file_path,"w")
    textfile.writelines(text)
    textfile.close()
    cmd = [spell_check_file_path,text_file_path, dict_file_path]
    tmp=subprocess.check_output(cmd, universal_newlines=True)
    misspelled = tmp.strip().replace("\n",", ")
    return misspelled


@app.route("/")
def home(): 
    return redirect(url_for("login"))


@app.route("/register", methods = ["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("spell_check"))
    if request.method == "POST":
        username = request.form["uname"]
        password = request.form["pword"]
        twofa = request.form["2fa"]
        if not username or not password or not twofa:
            flash("Failure: Empty Field(s)", "failure")
            return render_template("register.html")
        user = User.query.filter_by(username=username).first()
        if(not user):
            if(not isValidTwoFA(twofa)):
                flash("Failure: Invalid 2FA", "failure")
            else:
                addUser(username, password, twofa)
                flash("Success: Account registered", "success")
        else:
            flash("Failure: Username already registered", "failure")
    return render_template("register.html")
    
@app.route("/login", methods = ["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("spell_check"))
    if request.method == "POST":
        username = request.form["uname"]
        password = request.form["pword"]
        twofa = request.form["2fa"]
        if not username or not password or not twofa:
            flash("Failure: Empty Field(s)", "failure")
            return render_template("login.html")
        user = User.query.filter_by(username=username).first()
        if(user):
            if(sha256_crypt.verify(password, user.password)):
                if(user.twofa == twofa):
                    session["user_id"] = user.id
                    flash("Success: User logged in", "success")
                    return redirect(url_for("spell_check"))
                else:
                    flash("Failure: Incorrect Two-factor", "failure")
            else:
                flash("Failure: Incorrect password", "failure")
        else:
            flash("Failure: Incorrect username", "failure")
    return render_template("login.html")

@app.route("/spell_check", methods = ["GET", "POST"])
def spell_check():
    if "user_id" not in session:
        abort(401)
    user = User.query.filter_by(id=session["user_id"]).first()
    if request.method == "POST":
        textout = request.form["inputtext"]
        if not textout:
            flash("Failure: Empty Field", "failure")
            return render_template("spell_check_input.html")
        misspelled = findMisspelled(textout)
        addQueryRecord(user.username, textout, misspelled)
        return render_template("spell_check_output.html", textout = textout, misspelled = misspelled, isAdmin=(user.username == "admin"))
    if request.method == "GET":
        return render_template("spell_check_input.html", isAdmin=(user.username == "admin"))

@app.route("/logout")
def logout():
    if "user_id" in session:
        session.clear()
        flash("Success: User logged out", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)