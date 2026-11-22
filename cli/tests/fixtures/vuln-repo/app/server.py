import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    name = request.args.get("name")
    db = sqlite3.connect("app.db")
    # SQL injection: request input is concatenated into the query
    rows = db.execute("SELECT * FROM users WHERE name = '" + name + "'").fetchall()
    return str(rows)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c1 " + host, shell=True)
