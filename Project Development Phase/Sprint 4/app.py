from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, FloatField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import pickle
import numpy as np
import sklearn

model = pickle.load(open("wqi.pkl", "rb"))

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class WaterQualityIndex(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    StationCode = db.Column(db.Integer, nullable=False)
    State = db.Column(db.String(40), nullable=False)
    Temp = db.Column(db.Float, nullable=False)
    do = db.Column(db.Float, nullable=False)
    ph = db.Column(db.Float, nullable=False)
    co = db.Column(db.Integer, nullable=False)
    bod = db.Column(db.Float, nullable=False)
    na = db.Column(db.Float, nullable=False)
    tc = db.Column(db.Integer, nullable=False)
    Year = db.Column(db.Integer, nullable=False)
    WQI = db.Column(db.Float, nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class WQIForm(FlaskForm):
    StationCode = IntegerField(validators=[
                           InputRequired()], render_kw={"placeholder": "Station Code"})

    State = StringField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "State"})
    Temp = FloatField(validators=[
                             InputRequired()], render_kw={"placeholder": "Temp"})
    do = FloatField(validators=[
                             InputRequired()], render_kw={"placeholder": "D.O"})
    ph = FloatField(validators=[
                             InputRequired()], render_kw={"placeholder": "PH"})
    co = IntegerField(validators=[
                             InputRequired()], render_kw={"placeholder": "Conductivity"})
    bod = FloatField(validators=[
                             InputRequired()], render_kw={"placeholder": "B.O.D"})
    na = FloatField(validators=[
                             InputRequired()], render_kw={"placeholder": "Nitratenen"})
    tc = IntegerField(validators=[
                             InputRequired()], render_kw={"placeholder": "Coliform"})
    Year = IntegerField(validators=[
                             InputRequired()], render_kw={"placeholder": "Year"})
    submit = SubmitField('Predict')

class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = WQIForm()
    if form.validate_on_submit():
        feature_val = []
        feature_val.append(form.Temp.data)
        feature_val.append(form.do.data)
        feature_val.append(form.ph.data)
        feature_val.append(form.co.data)
        feature_val.append(form.bod.data)
        feature_val.append(form.na.data)
        feature_val.append(form.tc.data)
        float_features = [float(x) for x in feature_val]
        features = [np.array(float_features)]
        prediction = model.predict(features)
        new_data = WaterQualityIndex(StationCode=form.StationCode.data, State =form.State.data, Temp=form.Temp.data, do=form.do.data, ph=form.ph.data, co=form.co.data, bod=form.bod.data, na=form.na.data, tc=form.tc.data, Year=form.Year.data, WQI=prediction )
        db.session.add(new_data)
        db.session.commit()
        return render_template('dashboard.html',form=form, prediction_text = "The water quality index is {}".format(prediction))

    return render_template('dashboard.html',form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)
    
"""
@app.route("/predict", methods=['GET', 'POST'])
def predict():
    form = WQIForm()
    if form.validate_on_submit():
        feature_val = []
        feature_val.append[form.Temp.data]
        feature_val.append[form.do.data]
        feature_val.append[form.ph.data]
        feature_val.append[form.co.data]
        feature_val.append[form.bod.data]
        feature_val.append[form.na.data]
        feature_val.append[form.tc.data]
        float_features = [float(x) for x in feature_val]
        features = [np.array(float_features)]
        prediction = model.predict(features)
        new_data = WaterQualityIndex(StationCode=form.StationCode.data, State =form.State.data, Temp=form.Temp.data, DO=form.do.data, PH=form.ph.data, Conductivity=form.co.data, BOD=form.bod.data, Nitratenen=form.na.data, Coliform=form.tc.data, Year=form.Year.data, WQI=prediction )
        db.session.add(new_data)
        db.session.commit()
    return render_template("dashboard.html", form=form)
"""


if __name__ == "__main__":
    app.run(debug=True)
