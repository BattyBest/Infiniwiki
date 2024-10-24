
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Length, Regexp, EqualTo, Email, Optional, ValidationError
from openai import OpenAI
from threading import Thread
import pickle
import re
from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    current_user,
    logout_user,
    login_required,
)
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import select, update
from apscheduler.schedulers.background import BackgroundScheduler
import datetime
import shutil
import json
import os
import atexit

login_manager = LoginManager()
login_manager.session_protection = "strong"
login_manager.login_view = "login"
login_manager.login_message_category = "info"
db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
scheduler = BackgroundScheduler()
sites = {
    "example": "you found the example site! congrats!"
}

class User(UserMixin, db.Model):
    global config
    __tablename__ = "user"
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    pwd = db.Column(db.String(300), nullable=False, unique=False)
    banned = db.Column(db.Boolean, server_default='f', default=False)
    generations = db.Column(db.Integer, server_default='0')

    def __repr__(self):
        return '<User %r>' % self.username
    
class register_form(FlaskForm):
    username = StringField(
        validators=[
            InputRequired(),
            Length(3, 20, message="Usernames must be 3-20 characters long."),
            Regexp(
                "^[A-Za-z][A-Za-z0-9_.]*$",
                0,
                "Usernames must have only letters, " "numbers, dots or underscores",
            ),
        ]
    )
    pwd = PasswordField(validators=[InputRequired(), Length(8, 72)])
    cpwd = PasswordField(
        validators=[
            InputRequired(),
            Length(8, 72),
            EqualTo("pwd", message="Passwords dont match."),
        ]
    )
    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError("Email already registered.")

    def validate_uname(self, uname):
        if User.query.filter_by(username=uname.data).first():
            raise ValidationError("Username already taken.")

class login_form(FlaskForm):
    username = StringField(
        validators=[
            InputRequired(),
            Regexp(
                "^[A-Za-z][A-Za-z0-9_.]*$",
                0,
                "Usernames must have only letters, " "numbers, dots or underscores",
            ),
        ]
    )
    pwd = PasswordField(validators=[InputRequired()])

class initadmin_form(FlaskForm):
    pwd = PasswordField(validators=[InputRequired(), Length(8, 72)])
    cpwd = PasswordField(
        validators=[
            InputRequired(),
            Length(8, 72),
            EqualTo("pwd", message="Passwords dont match."),
        ]
    )

give_generations_job = None;

webpages_autosave_job = None;

generating_sites = {
}

def has_generations():
    if not(current_user.is_authenticated):
        return False
    return current_user.generations > 0

def ensure_has_generations():
    if current_user.username == "Admin":
        return True
    if not(has_generations()):
        flash("You don't have any generations left or are not logged in. Next generation is in " + str((give_generations_job.next_run_time - datetime.datetime.now(datetime.timezone.utc))), 'danger')
        return False
    else:
        current_user.generations -= 1
        return True

def normalize_pagestr(pagestr):
    pagestr = pagestr.lower().strip(" []").replace("_", " ").replace("-", " ")
    return pagestr

def init():
    global client, sites, config, give_generations_job, webpages_autosave_job
    app = Flask(__name__);

    try:
        with open("config.json", "r") as file:
            config = json.load(file)
    except FileNotFoundError:
        shutil.copy("default_config.json", "config.json")
        with open("config.json", "r") as file:
            config = json.load(file)

    app.secret_key = config['secret_key']
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///users.db"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

    client = OpenAI(base_url=config["AIModels"]["url"], api_key=config["AIModels"]["key"])

    login_manager.init_app(app)
    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    give_generations_job = scheduler.add_job(add_gen_to_all_users, 'interval', minutes=config["regen_interval_minutes"])
    atexit.register(save_webpage_pkb)
    webpages_autosave_job = scheduler.add_job(save_webpage_pkb, 'interval', minutes=10)
    scheduler.start()
    try:
        with open("saved_sites.pkb", "rb") as file:
            sites = pickle.load(file)
    except FileNotFoundError:
        pass
    app.app_context().push()
    from flask_migrate import upgrade,migrate as migrate2,init,stamp

    if not(os.path.isdir('migrations')):
        init()
        stamp()
        migrate2()
        upgrade()

    return app

def save_webpage_pkb():
    global sites, config
    with open("saved_sites.pkb", "wb") as file:
        pickle.dump(sites, file)

def add_gen_to_all_users():
    with app.app_context():
        try:
            db.session.execute(update(User).where(User.generations < config["max_gen_store"]).values(generations = User.generations + 1))
            db.session.commit()
        except Exception as e:
            print(e)

app = init()

@app.before_request
def ensure_curr_user_isnt_banned():
    db.session.commit()
    if current_user.is_authenticated and current_user.banned:
        flash("You have been banned.", "danger")
        return logout()
    else:
        return

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Didnt work very well so retired at the moment.
#def add_hyperlink(pagestr):
#    # From old regex based system
#    # regex_detect = r";?([a-zA-Z \-\_]*);"
#    # 
#    # regex_sub = r"(?<=[^a-zA-Z\/])({0})(?=[^a-zA-Z\/])"
#    # subst = "<a href='\\g<1>'>\\g<1></a>"
#
#    coder_model = config["AIModels"]["coder_model"]
#    page = sites[pagestr]
#
#    # Alternate system of identify then change. Does not work very well if the coder model is stupid on the literary front, which often happens on local models, so commented out. If using a smart coder model, this is preffered.
## 
#    # generating_sites[pagestr] = " ";
#    # model = config["AIModels"]["refiner_model"]
#    # completions = client.chat.completions.create(model=model, messages=[
#    #     {"role": "system","content": "You identify potential candidates for hyperlinking in a website. You only identify candidates that arent already hyperlinks. If a word is already hyperlinked to another page, you exclude it from your response. You include plenty of new things to hyperlink. For a website given by the user, output a list of words or phrases that could be hyperlinked to another site and are already not hyperlinked. Seperate each hyperlinking candidate with a semicolon (';'). You output only the resulting list of linking candidates, and nothing else. You do not address the user. You output nothing other than the list of candidates seperated by semicolons (';')."},
#    #     {"role": "system","content": "You always respond in this format: '[item 1];[item 2];[item3];'"},
#    #     {"role": "system","content": "Example of your response for the website snippet 'In the 1800's, Mary Jane made a profound discovery. This discovery was the <a href=/page/\"Bloop Theorem\">Bloop Theorem</a>. She proved this with a lot of sophistry and antidisestablismentarianism thinking. She extensively utilized the printing press to spread this discovery.' would be 'Philosophy in the early 1800's;Mary Jane;Sophistry;Antidisestablishmentarianism;Agriculture;History of the Printing Press;'"},
#    #     {"role":"user","content": "Identify hyperlinking candidates in this website, remember only include new hyperlinks and to end it with a semicolon (';') : " + page}
#    # ],n=1,stop=None,temperature=0, stream=True, frequency_penalty=2)
#    # for resp in completions:
#    #     if not(resp.choices[0].delta.content is None):
#    #         generating_sites[pagestr] += resp.choices[0].delta.content
#    # list = generating_sites[pagestr]
#    # if list[-1] != ';':
#    #     list += ';'
## 
#    # generating_sites[pagestr] = " ";
#    # completions = client.chat.completions.create(model=coder_model, messages=[
#    #     {"role": "system","content": "You add hyperlinks to websites. Add a html hyperlink (<a>) with a href attribute of '/page/[topic]' for all and EVERY single topic, concept, idea and key historical figure in the websites text. You do not ever just return the same thing, you always add at least 10 hyperlinks, but often more. You always keep the existing content on the website. You start your response with the answer, and do not present it."},
#    #     {"role":"user","content": "Use these tags:\n" + list + "\nHyperlink this website, add many links: " + page}
#    # ],n=1,stop=None,temperature=0, stream=True, frequency_penalty=0)
#    # for resp in completions:
#    #     if not(resp.choices[0].delta.content is None):
#    #         generating_sites[pagestr] += resp.choices[0].delta.content
#
#    generating_sites[pagestr] = " ";
#    completions = client.chat.completions.create(model=coder_model, messages=[
#        {"role": "system","content": "You add hyperlinks to websites. Add a html hyperlink (<a>) with a href attribute of '/page/[topic]' for all and EVERY single topic, concept, idea and key historical figure in the websites text. You do not ever just return the same thing, you always add at least 10 hyperlinks, but often more. You always keep the existing content on the website. You start your response with the answer, and do not present it."},
#        {"role":"user","content": "Hyperlink this website, add many links: " + page}
#    ],n=1,stop=None,temperature=0.2, stream=True, frequency_penalty=0.5)
#    for resp in completions:
#        if not(resp.choices[0].delta.content is None):
#            generating_sites[pagestr] += resp.choices[0].delta.content
#    message = generating_sites[pagestr]
#    if '```' in message:
#        message = str.split(message, '```')[1]
#
#    sites[pagestr] = generating_sites[pagestr].strip(" abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
#
#    generating_sites[pagestr] = "Generated!!"

def prettify(pagestr):
    regex = r"(?<=href=[\"\'])(?:https://)?[a-zA-Z0-9\.\-\_]*[\/\#]?(?:[a-zA-Z\_\-]*\/)*([a-zA-Z\_\-]*)#?([a-zA-Z\_\-]*)(?=[\"\'])"
    subst = "/page/\\g<1> \\g<2>"

    page = sites[pagestr]

    model = config["AIModels"]["coder_model"]
    generating_sites[pagestr] = " ";
    completions = client.chat.completions.create(model=model, messages=[
        {"role": "system","content": "You improve existing webpage code. You only use html5, css, and js. You always include lots of hyperlinks, and always keep existing hyperlinks. You make the websites look pretty. You prettify websites. You use lots of css to make websites more pretty and beautiful. You dont compromise on function for aesthetic. You always use gradients and subtle colors. You always add lots of hover effects. You always include all the things needed yourself, and never leave work to the user. You only output the html, css and js code. You output nothing else. You always output the css inline, and use classes to keep the code tidy. Your responses include only website code. Your responses exclude anything not code or content. You organize the content given on the website into an easily readable format. You also turn any text that says '[[[whatever]]]' into a link that goes to '/page/whatever'. You always make sure the website is accesible. Access resources (like images or svgs) with '/resource/[whatever]'"},
        {"role":"user","content": "Prettify the following website, use lots of subtle colors and gradients: " + page}
    ],n=1,stop=None,temperature=1.1, stream=True, frequency_penalty=0)
    for resp in completions:
        if not(resp.choices[0].delta.content is None):
            generating_sites[pagestr] += resp.choices[0].delta.content
    message = generating_sites[pagestr]
    if '```' in message:
        message = str.split(message, '```')[1]
    message = re.sub(regex, subst, message, 0, re.MULTILINE)
    sites[pagestr] = message.strip(" abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

    generating_sites[pagestr] = "Generated!!"


def generate(pagestr):
    regex = r"(?<=href=[\"\'])(?:https://)?[a-zA-Z0-9\.\-\_]*[\/\#]?(?:[a-zA-Z\_\-]*\/)*([a-zA-Z\_\-]*)#?([a-zA-Z\_\-]*)(?=[\"\'])"
    subst = "/page/\\g<1> \\g<2>"

    global generating_sites
    pagestr = normalize_pagestr(pagestr)
    generating_sites[pagestr] = "";
    thinker_model = config["AIModels"]["thinker_model"]
    generator = client.chat.completions.create(model=thinker_model, messages=[
        {"role": "system","content": "You generate interesting information and fun facts. You always generate lots of info about the topic the user specifies. You only output the info that the user wants. You always write a lot. You write around 3 long paragraphs. If you encounter a topic from the user that is something that is ambigious or unclear, you write instead a disambiguation (you continue without asking for clarification), explaining what it can refer to, and giving a list of every possible meaning. If writing the disambiguation, you need to include every single possible meaning of the word or phrase. You start your response with the answer, and do not present it."},
        {"role":"user","content": "Write about anything. Talk about a variety of content. Write about 10 topics, and one sentence a topic." if pagestr == "random" else "Write a large amount of info about " + pagestr}
    ],n=1,stop=None,temperature=0.8, stream=True, max_tokens=1500)
    for resp in generator:
        if not(resp.choices[0].delta.content is None):
            generating_sites[pagestr] += resp.choices[0].delta.content
    info = generating_sites[pagestr]
    refiner_model = config["AIModels"]["refiner_model"]
    generating_sites[pagestr] = "";
    generator = client.chat.completions.create(model=refiner_model, messages=[
        {"role": "system","content": "You generate tags for written content. These tags are in the format of '[[[topic]]]' such as '[[[philosophy in the early 1800's]]]' or '[[[analytical chemistry]]]'. These tags are akin to where hyperlinks would go on a webpage. You generate large amounts of these tags, one for every distinct concept or key figure in the text. You only generate the tags and nothing else. You start your response with the answer, and do not present it."},
        {"role":"user","content": "Generate markers according to the following text: " + info}
    ],n=1,stop=None,temperature=1.1, stream=True, max_tokens=1500)
    for resp in generator:
        if not(resp.choices[0].delta.content is None):
            generating_sites[pagestr] += resp.choices[0].delta.content
    tag_info = generating_sites[pagestr]
    coder_model = config["AIModels"]["coder_model"]
    generating_sites[pagestr] = " ";
    completions = client.chat.completions.create(model=coder_model, messages=[
        {"role": "system","content": "You generate a website with html, css, and javascript based on a given reference text and tags. You use the reference text to add content to the website. You integrate the given tags in to the given reference text seamlessly, and you keep the tags in the '[[[whatever]]]' format, with each tag '[[[something]]]' corresponding to a link to '/page/something'. You always add all of the tags in to the text. You cannot access images or svgs from the server. You start your response with the answer, and do not present it."},
        {"role":"user","content": "Generate a website. Add all and every single one of these tags into the text content as hyperlinks: " + tag_info + "\nUse this as reference text for the text content: " + info}
    ],n=1,stop=None,temperature=0, stream=True, frequency_penalty=0)
    for resp in completions:
        if not(resp.choices[0].delta.content is None):
            generating_sites[pagestr] += resp.choices[0].delta.content
    message = generating_sites[pagestr]
    message = re.sub(regex, subst, message, 0, re.MULTILINE)
    if '```' in message:
        message = str.split(message, '```')[1]
    generating_sites[pagestr] = " ";
    completions = client.chat.completions.create(model=coder_model, messages=[
        {"role": "system","content": "You add hyperlinks to websites. Add a html hyperlink (<a>) with a href attribute of '/page/[topic]' for all and EVERY single topic, concept, idea and key historical figure in the websites text. You do not ever just return the same thing, you always add at least 10 hyperlinks, but often more. You always keep the existing content on the website. You start your response with the answer, and do not present it."},
        {"role":"user","content": "Hyperlink this website, add many links: " + message}
    ],n=1,stop=None,temperature=0.2, stream=True, frequency_penalty=0.5)
    for resp in completions:
        if not(resp.choices[0].delta.content is None):
            generating_sites[pagestr] += resp.choices[0].delta.content
    message = generating_sites[pagestr]
    if '```' in message:
        message = str.split(message, '```')[1]
    generating_sites[pagestr] = " ";
    completions = client.chat.completions.create(model=coder_model, messages=[
        {"role": "system","content": "You improve existing webpage code. You only use html5, css, and js. You always include lots of hyperlinks, and always keep existing hyperlinks. You make the websites look pretty. You prettify websites. You use lots of css to make websites more pretty and beautiful. You dont compromise on function for aesthetic. You always use gradients and subtle colors. You always add lots of hover effects. You always include all the things needed yourself, and never leave work to the user. You only output the html, css and js code. You output nothing else. You always output the css inline. Your responses include only website code. You never address the user. Your responses exclude anything not code or content. You organize the content given on the website into an easily readable format. You also turn any text that says '[[[whatever]]]' into a link that goes to '/page/whatever'. You always make sure the website is accesible. You cannot access images or svgs from the server. You start your response with the answer, and do not present it."},
        {"role":"user","content": "Prettify the following website, use lots of subtle colors and gradients: " + message}
    ],n=1,stop=None,temperature=1.1, stream=True, frequency_penalty=0)
    for resp in completions:
        if not(resp.choices[0].delta.content is None):
            generating_sites[pagestr] += resp.choices[0].delta.content
    message = generating_sites[pagestr]
    if '```' in message:
        message = str.split(message, '```')[1]
    message = re.sub(regex, subst, message, 0, re.MULTILINE)

    regex = r"\[\[\[([a-zA-Z _]*)\]\]\]"
    
    subst = "<a href=\"/page/\\g<1>\">\\g<1></a>"

    message = re.sub(regex, subst, message, 0, re.MULTILINE)
    sites[pagestr] = message.strip(" abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
    generating_sites[pagestr] = "Generated!!"

@app.route("/")
def index():
    global give_generations_job
    if User.query.filter_by(username="Admin").first():
        return render_template("index.html")
    else:
        return redirect("/makeinitadminaccount/")
    
@app.route("/api/next_gen_keys")
def calc_next_gen_keys():
    return str((give_generations_job.next_run_time - datetime.datetime.now(datetime.timezone.utc))).split(".")[0]

@app.route("/api/current_user_gen_keys")
def current_user_gen_keys():
    db.session.commit()
    return str(current_user.generations)

@app.route("/login/", methods=("GET", "POST"), strict_slashes=False)
def login():
    form = login_form()

    if form.validate_on_submit():
        try:
            user = User.query.filter_by(username=form.username.data).first()
            if not( user is None ) and bcrypt.check_password_hash(user.pwd, form.pwd.data):
                login_user(user)
                return redirect("/")
            else:
                flash("Invalid username or password.", "danger")
        except Exception as e:
            flash(e, "danger")

    return render_template("auth.html",form=form)

@app.route("/makeinitadminaccount/", methods=("GET", "POST"), strict_slashes=False)
def initadminacc():
    form = initadmin_form()

    if User.query.filter_by(username="Admin").first():
        flash(f"No, you can't be admin.", "danger")
        return redirect("/login/")

    if form.validate_on_submit():
        try:
            pwd = form.pwd.data
            
            newuser = User(
                username="Admin",
                pwd=bcrypt.generate_password_hash(pwd),
            )
    
            db.session.add(newuser)
            db.session.commit()
            flash(f"Admin account succesfully created.", "success")
            return redirect("/login/")

        except Exception as e:
            flash(e, "danger")

    return render_template("makeadminuser.html",form=form)

@app.route("/register/", methods=("GET", "POST"), strict_slashes=False)
def register():
    global config
    form = register_form()

    if form.validate_on_submit():
        try:
            pwd = form.pwd.data
            username = form.username.data
            
            newuser = User(
                username=username,
                pwd=bcrypt.generate_password_hash(pwd),
                generations = config["start_with_gens"]
            )
    
            db.session.add(newuser)
            db.session.commit()
            flash(f"Account Succesfully created", "success")
            return redirect("/login")

        except Exception as e:
            flash(e, "danger")

    return render_template("auth.html",form=form)

@app.route("/logout/")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/config/", methods=["GET", "POST"])
@login_required
def changeconfig():
    global config
    if current_user.username != "Admin":
        flash(f"No, you can't be admin.", "danger")
        return redirect("/login/")
    

    if request.method == "POST":
        config["secret_key"] = request.form.get("secret_key")
        config["AIModels"]["url"] = request.form.get("AIModelssuburl")
        config["AIModels"]["key"] = request.form.get("AIModelssubkey")
        config["AIModels"]["thinker_model"] = request.form.get("AIModelssubthinker_model")
        config["AIModels"]["coder_model"] = request.form.get("AIModelssubcoder_model")
        config["AIModels"]["refiner_model"] = request.form.get("AIModelssubrefiner_model")
        config["need_login_for_gen"] = not(request.form.get("need_login_for_gen") is None) # This is how you check checkboxes believe it or not...
        config["regen_interval_minutes"] = int(request.form.get("regen_interval_minutes"))
        config["max_gen_store"] = int(request.form.get("max_gen_store"))
        config["start_with_gens"] = int(request.form.get("start_with_gens"))

        with open("config.json", "w") as file:
            json.dump(config, file)

        return redirect("/")


    if request.method == "GET":
        r = json.dumps(config)
        loaded_r = json.loads(r)
        return render_template("config.html", json=loaded_r)


@app.route("/generating/<pagestr>", methods=["GET", "POST"])
def halfGenPage(pagestr):
    pagestr = normalize_pagestr(pagestr)
    global generating_sites
    if pagestr in generating_sites:
        if "Generated!!" == generating_sites[pagestr]:
            del generating_sites[pagestr]
            return "Generated!!"
        return generating_sites[pagestr]
    return "Generated!!"

@app.route("/improve/<pagestr>", methods=["GET", "POST"])
def improvePage(pagestr):
    pagestr = normalize_pagestr(pagestr)
    if pagestr in sites:
        return render_template("improve.html", pagestr=pagestr)
    else:
        return f"Page not found. <a href='/page/{pagestr}'>Make It?</a>"

@app.route("/hyperlink/<pagestr>", methods=["GET", "POST"])
def hyperlink(pagestr):
    return "This feature has been temporarily retired."
#    if config["need_login_for_gen"] and not(current_user.is_authenticated):
#        flash("You need to be logged in to do that.", "danger")
#        return redirect("/login")
#    if not(ensure_has_generations()):
#        return redirect("/")
#    pagestr = normalize_pagestr(pagestr)
#    global sites, generating_sites
#    if pagestr in sites:
#        generating_sites[pagestr] = "";
#        Thread(target=add_hyperlink, args=(pagestr,)).start()
#        return redirect("/generatingwaiter/" + pagestr)
#    else:
#        return f"Page not found. <a href='/page/{pagestr}'>Make It?</a>"
    
@app.route("/prettify/<pagestr>", methods=["GET", "POST"])
def makepretty(pagestr):
    if config["need_login_for_gen"] and not(current_user.is_authenticated):
        flash("You need to be logged in to do that.", "danger")
        return redirect("/login")
    if not(ensure_has_generations()):
        return redirect("/")
    pagestr = normalize_pagestr(pagestr)
    global sites, generating_sites
    if pagestr in sites:
        generating_sites[pagestr] = "";
        Thread(target=prettify, args=(pagestr,)).start()
        return redirect("/generatingwaiter/" + pagestr)
    else:
        return f"Page not found. <a href='/page/{pagestr}'>Make It?</a>"

@app.route("/generatingwaiter/<pagestr>", methods=["GET", "POST"])
def halfGenWaiterPage(pagestr):
    pagestr = normalize_pagestr(pagestr)
    return render_template("answer.html", pagestr=pagestr)

@app.route("/page/<pagestr>")
def showPage(pagestr):
    pagestr = normalize_pagestr(pagestr)
    global sites, generating_sites
    if pagestr in sites:
        return sites[pagestr] + f'<br /><a href="/improve/{pagestr}">Improve this page</a>'
    elif pagestr in generating_sites:
        return redirect("/generatingwaiter/" + pagestr)
    else:
        if config["need_login_for_gen"] and not(current_user.is_authenticated):
            flash("Page isnt generated; wiki requires users to be logged in to generate pages.", "danger")
            return redirect("/login")
        if not(ensure_has_generations()):
            return redirect("/")
        generating_sites[pagestr] = "";
        Thread(target=generate, args=(pagestr,)).start()
        return redirect("/generatingwaiter/" + pagestr)

@app.route("/regenerate/<pagestr>", methods=["GET"])
def regenerate(pagestr):
    global sites
    if config["need_login_for_gen"] and not(current_user.is_authenticated):
        flash("You need to be logged in to do that.", "danger")
        return redirect("/login")
    if not(ensure_has_generations()):
        return redirect("/")
    
    pagestr = normalize_pagestr(pagestr)
    if pagestr in sites:
        del sites[pagestr]
    return redirect("/page/" + pagestr, code=303)

@app.route("/favicon.ico")
def favicon():
    return redirect(app.url_for('static', filename='infinity.ico'))

@app.route("/css.css")
def css():
    return redirect(app.url_for('static', filename='css.css'))