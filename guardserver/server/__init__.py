from flask import Flask, redirect
app = Flask(__name__, static_folder="../static")
app.config.from_object('config')

@app.route("/")
def index_route():
    return redirect("/static/index.html")

from issues import get_issues
from filters import filter_by_commit
