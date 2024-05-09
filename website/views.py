from flask import Blueprint, render_template

views = Blueprint('views', __name__)

@views.route('/')
def home():
    """Render the main page."""
    return render_template('home.html')