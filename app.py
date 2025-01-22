from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime
import requests

# App setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///med_monitor.db'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class Visit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    reason = db.Column(db.String(255), nullable=False)
    notes = db.Column(db.String(500), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', back_populates='visits')

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    drugs = db.relationship("Drug", backref="owner", lazy=True)

# Drug model
class Drug(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    wiki_link = db.Column(db.String(300), nullable=True)

class DrugInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    wiki_link = db.Column(db.String(300), nullable=False)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("Login failed. Check your username and password.", "danger")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = bcrypt.generate_password_hash(request.form["password"]).decode("utf-8")
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for("login"))
    return render_template("login.html", register=True)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    # Fetch all available drugs for the dropdown
    all_drugs = DrugInfo.query.all()

    # Fetch user's medications
    user_drugs = Drug.query.filter_by(user_id=current_user.id).all()

    # Get the names of the drugs the user has added
    drug_names = [drug.name for drug in user_drugs]

    # Check for interactions between the drugs the user has added
    interactions, drug_interactions = check_interactions(drug_names)

    if request.method == 'POST':
        drug_id = request.form.get('drug_id')
        selected_drug = DrugInfo.query.get(drug_id)

        if selected_drug:
            # Save the selected drug to user's medications
            new_user_drug = Drug(name=selected_drug.name, user_id=current_user.id, wiki_link=selected_drug.wiki_link)
            db.session.add(new_user_drug)
            db.session.commit()
            flash(f'{selected_drug.name} added to your medications.', 'success')
            return redirect(url_for('dashboard'))

    return render_template(
        'dashboard.html',
        all_drugs=all_drugs,
        drugs=user_drugs,
        interactions=interactions,  # Pass interactions to the template
    )



@app.route('/appointments', methods=['GET', 'POST'])
@login_required
def appointments():
    # Get all drugs for the current user
    drugs = Drug.query.filter_by(user_id=current_user.id).all()

    # Check for interactions
    interactions = check_interactions([drug.name for drug in drugs])

    # Get all visits for the current user
    visits = Visit.query.filter_by(user_id=current_user.id).all()

    if request.method == 'POST':
        # Handle adding drugs
        if 'drug_name' in request.form:
            drug_name = request.form['drug_name']
            new_drug = Drug(name=drug_name, user_id=current_user.id)
            db.session.add(new_drug)
            db.session.commit()
            flash(f'{drug_name} added to your medications.', 'success')
        
        # Handle adding visits with custom appointment date
        if 'reason' in request.form:
            reason = request.form['reason']
            notes = request.form['notes']
            appointment_date = request.form['appointment_date']  # Get the custom date from the form
            
            # Convert the date string to a datetime object
            appointment_date = datetime.strptime(appointment_date, '%Y-%m-%d')
            
            # Create new visit with the custom date
            new_visit = Visit(reason=reason, notes=notes, date=appointment_date, user_id=current_user.id)
            db.session.add(new_visit)
            db.session.commit()
            flash(f'Visit on {appointment_date.strftime("%Y-%m-%d")} added to your history.', 'success')
            return redirect(url_for('appointments'))

    return render_template('appointments.html', drugs=drugs, interactions=interactions, visits=visits)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))

# Simplified interaction checker (mocked API)
def check_interactions(drugs):
    interactions = []
    drug_interactions = {}  # Dictionary to store drugs involved in interactions
    
    # Sample interactions between drugs (for demonstration)
    known_interactions = {
        ("Aspirin", "Ibuprofen"): "Warning: Aspirin and Ibuprofen may increase the risk of bleeding.",
        ("Aspirin", "Warfarin"): "Warning: Aspirin and Warfarin may increase the risk of bleeding.",
        ("Ibuprofen", "Warfarin"): "Warning: Ibuprofen and Warfarin may increase the risk of bleeding."
    }
    
    # Check all combinations of the drugs the user has entered
    for i in range(len(drugs)):
        for j in range(i + 1, len(drugs)):
            drug_pair = tuple(sorted([drugs[i], drugs[j]]))  # Sort the pair to match our known_interactions
            if drug_pair in known_interactions:
                interactions.append(known_interactions[drug_pair])
                
                # Mark the drugs involved in the interaction
                drug_interactions[drugs[i]] = True
                drug_interactions[drugs[j]] = True

    return interactions, drug_interactions

def populate_drug_info():
    drugs = [
        {"name": "Aspirin", "wiki_link": "https://en.wikipedia.org/wiki/Aspirin"},
        {"name": "Ibuprofen", "wiki_link": "https://en.wikipedia.org/wiki/Ibuprofen"},
        {"name": "Warfarin", "wiki_link": "https://en.wikipedia.org/wiki/Warfarin"},
    ]
    for drug in drugs:
        if not DrugInfo.query.filter_by(name=drug['name']).first():
            new_drug = DrugInfo(name=drug['name'], wiki_link=drug['wiki_link'])
            db.session.add(new_drug)
    db.session.commit()

@app.route("/ai-assistant", methods=["GET", "POST"])
@login_required
def ai_assistant():
    message = ""
    if request.method == "POST":
        user_input = request.form["user_input"]
        message = f"You: {user_input}"
    return render_template("ai_assistant.html", message=message)


User.visits = db.relationship('Visit', back_populates='user', lazy=True)



# Run app
if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Ensure this runs within the application context
        populate_drug_info()
        
    app.run(debug=True)
