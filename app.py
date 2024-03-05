from flask import Flask, request, jsonify
from models.user_model import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from bcrypt import hashpw, gensalt, checkpw


app = Flask(__name__)
app.config["SECRET_KEY"] = "some-secret-string"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
login_manager = LoginManager()

db.init_app(app)
login_manager.init_app(app)

login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:    
        user = User.query.filter_by(username=username).first()
        if user and checkpw(str.encode(password), user.password):
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({"message": "Success"}), 200
        else:
            return jsonify({"error": "Invalid credentials"}), 401
    
    return jsonify({"error": "Invalid data"}), 400

@app.route("/signup", methods=["POST"])
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Invalid data"}), 400
    
    userAlreadyExists = User.query.filter_by(username=username).first()
    if userAlreadyExists:
        return jsonify({"error": "User already exists"}), 400
    
    hashed_pass = hashpw(str.encode(password), gensalt())

    user = User(username=username, password=hashed_pass)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User created"}), 201

@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logged out"}), 200

@app.route("/user/<int:id_user>", methods=["GET"])
@login_required
def get_user(id_user):
    if not id_user:
        return jsonify({"error": "Invalid data"}), 400
    user = User.query.filter_by(id=id_user).first()
    if user:
        userReturn = {
            "id": user.id,
            "username": user.username,
        }
        return jsonify({"user": userReturn}), 200
    return jsonify({"error": "User not found"}), 404

@app.route("/user/<int:id_user>", methods=["PUT"])
@login_required
def update_user(id_user):
    data = request.json
    userExist = User.query.filter_by(id=id_user).first()
    if userExist and data.get("password"):
        new_password = hashpw(str.encode(data.get("password")), gensalt())
        userExist.password = new_password
        db.session.commit()
        return jsonify({"message": "User updated"}), 200

    return jsonify({"error": "Invalid data"}), 400

@app.route("/user/<int:id_user>", methods=["DELETE"])
@login_required
def delete_user(id_user):
    user = User.query.filter_by(id=id_user).first()
    if user and id_user != current_user.id:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted"}), 200
    return jsonify({"error": "User not found"}), 404

if __name__ == '__main__':
    app.run(debug=True)