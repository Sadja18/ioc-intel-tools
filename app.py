import os

from flask import Flask, jsonify, request

# from flask_cors import CORS
from dotenv import load_dotenv
from mongoengine import connect

from example_blueprint import example_blueprint
from domains_blueprint import domain_blueprint
from ip_blueprint import ip_blueprint




app = Flask(__name__)

app.config['DEBUG'] = os.getenv("DEBUG")
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

# CORS(app)

# Define a set of allowed IP addresses
allowed_ips = {'127.0.0.1','10.228.12.198', '10.228.13.115'}

# load env variables
load_dotenv()

# Get environment variables
mongodb_database = os.getenv("MONGODB_DATABASE")
user = os.getenv("MONGODB_USER")
password = os.getenv("MONGODB_PASSWORD")
host = os.getenv("MONGODB_HOST")
port = os.getenv("MONGODB_PORT")

# Construct a dictionary of connection parameters
connection_params = {}

if mongodb_database:
    connection_params["db"] = mongodb_database

if user and password:
    connection_params["user"] = user
    connection_params["password"] = password

if host:
    connection_params["host"] = host

if port:
    connection_params["port"] = int(port)

# Check if there are any parameters to connect
if connection_params:
    database = connect(**connection_params)
else:
    # Handle the case when no parameters are available
    database = connect("localsiem")


@app.before_request
def restrict_by_ip():
    # Get the IP address of the client making the request
    client_ip = request.remote_addr
    print(client_ip)
    print(connection_params)
    print(database)
    
    # Check if the client's IP is in the allowed set
    if client_ip not in allowed_ips:
        return "Access Denied", 403

# Define a custom error handler for 405 errors
@app.errorhandler(405)
def handle_method_not_allowed(error):
    return jsonify({"error": "Method not allowed"}), 405


app.register_blueprint(example_blueprint)
app.register_blueprint(domain_blueprint)
app.register_blueprint(ip_blueprint)



app.run(debug=True, host="0.0.0.0")