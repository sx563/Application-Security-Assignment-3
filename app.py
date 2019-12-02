from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask import escape
import subprocess 
from flask_wtf import CSRFProtect
import secrets
from passlib.hash import sha256_crypt


class User:
    def __init__(self, username, password, twofa):
        self.username = username
        self.password = password
        self.twofa = twofa
    def getPassword(self):
        return self.password
    def gettwofa(self):
        return self.twofa
    
Users = {}

def isRegisteredUser(username):
    global Users
    if username in Users:
        return True
    else:
        return False

def addUser(username, password, twofa):
    global Users
    Users[username] = User(username, sha256_crypt.hash(password), twofa)

def checkPassword(username, password):
    global Users
    if sha256_crypt.verify(password, Users[username].getPassword()):
        return True
    else:
        return False

def checktwofa(username, twofa):
    global Users
    if twofa == Users[username].gettwofa():
        return True
    else:
        return False

def isValidTwoFA(twofa):
    if len(twofa) != 11:
        return False
    for char in twofa:
        if not char.isdigit():
            return False
    return True


app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(256)
csrf = CSRFProtect(app)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_HTTPONLY = True
)

@app.after_request
def add_custom_headers(response):
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response



@app.route("/")
def home(): 
    return redirect(url_for("register"))


@app.route("/register", methods = ["GET", "POST"])
def register():
    if "username" in session:
        return redirect(url_for("spell_check"))
    if request.method == "POST":
        username = escape(request.form["uname"])
        password = escape(request.form["pword"])
        twofa = escape(request.form["2fa"])
        if not username or not password or not twofa:
            flash("Failure: Empty Field(s)", "failure")
            return render_template("register.html")
        if(not isRegisteredUser(username)):
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
    if "username" in session:
        return redirect(url_for("spell_check"))
    if request.method == "POST":
        username = escape(request.form["uname"])
        password = escape(request.form["pword"])
        twofa = escape(request.form["2fa"])
        if not username or not password or not twofa:
            flash("Failure: Empty Field(s)", "failure")
            return render_template("login.html")
        if(isRegisteredUser(username)):
            if(checkPassword(username, password)):
                if(checktwofa(username, twofa)):
                    session["username"] = username
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
    if "username" in session:
        if request.method == "POST":
            textout = request.form["inputtext"]
            if not textout:
                flash("Failure: Empty Field", "failure")
                return render_template("spell_check_input.html")
            spell_check_file_path = "./a.out"
            text_file_path = "./static/inputtext.txt"
            dict_file_path = "./static/wordlist.txt"
            textout = request.form['inputtext']
            textfile = open(text_file_path,"w")
            textfile.writelines(textout)
            textfile.close()
            cmd = [spell_check_file_path,text_file_path, dict_file_path]
            tmp=subprocess.check_output(cmd, universal_newlines=True)
            misspelled = tmp.strip().replace("\n",", ")
            return render_template("spell_check_output.html", textout = textout, misspelled = misspelled)
        if request.method == "GET":
            return render_template("spell_check_input.html")
    else:
        return redirect(url_for("login"))
    

@app.route("/logout")
def logout():
    session.clear()
    flash("Success: User logged out", "success")
    return redirect(url_for("login"))
    
if __name__ == "__main__":
    app.run(debug=True)