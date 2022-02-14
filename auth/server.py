from flask import Flask, jsonify, request
from flask_restful import Resource, Api
import requests
import json
import hashlib
import uuid

app = Flask(__name__)
api = Api(app)

graphql_url = "http://127.0.0.1:8080/v1/graphql"

create_user_query ='''
mutation($username: String, $password: String) {
  insert_user_one(
    object: {username: $username, password: $password}
  ){
    user_id
  }
}
'''

fetch_user_query ='''
 query ($username: String) {
  user(where: {username: {_eq: $username}}){
    user_id
    username
    password
  }
}
'''

insert_session_query ='''
mutation ($user_id: Int, $session_token: String) {
  insert_session_one(
    object: {user_id: $user_id, session_token: $session_token}
  ){
    session_id
  }
}
'''

fetch_session_query ='''
query($session_token: String) {
  session(where: {session_token: {_eq: $session_token}}){
    user_id
  }
}
'''

def graphql_query(query, variables):
    req = {
        'query': query,
        'variables': variables
    }
    headers = {"X-Hasura-Admin-Secret": "random"}
    res = requests.post(graphql_url, headers=headers, data = json.dumps(req))
    return res.json()

hash_salt = b'some_salt'

def hash_pass(password):
    key = hashlib.pbkdf2_hmac(
        'sha256', # The hash digest algorithm for HMAC
        password.encode('utf-8'), # Convert the password to bytes
        hash_salt, # Provide the salt
        100000 # It is recommended to use at least 100,000 iterations of SHA-256
       )
    return key.hex()



class Signup(Resource):

    def post(self):
        data = request.get_json(force=True)
        data['password'] = hash_pass(data['password'])
        res = graphql_query(create_user_query, data)
        if 'errors' not in res:
            return {"message": "user signup successful"}
        else:
            if res['errors'][0]['extensions']['code'] == 'constraint-violation':
                return {"error": "username already exists"}
            else:
                return {"error": "user signup unsuccessful"}

class Login(Resource):

    def post(self):
        data = request.get_json(force=True)
        username = data['username']
        password = data['password']
        res = graphql_query(fetch_user_query, {'username': username})
        if 'errors' not in res:
            if res['data']['user'] != []:
                user = res['data']['user'][0]
                if user['password'] == hash_pass(password):
                    session_tok = uuid.uuid4().hex
                    session_res = graphql_query(insert_session_query, {"user_id": user['user_id'], "session_token": session_tok})
                    if 'errors' not in session_res:
                        return {"session_token": session_tok}
                    else:
                        return {"error": "Login failed: cannot create session token"}

                else:
                    return {"error": "Login failed: wrong password"}
            else:
                return {"error": "Login failed: user not found"}
        else:
            return {"error": "internal error: cannot fetch user details"}

class Webhook(Resource):

    def get(self):
        print(request.headers)
        bearer = request.headers.get('Authorization')
        tok = bearer.split()[1]
        token_res = graphql_query(fetch_session_query, {"session_token": tok})
        if 'errors' not in token_res:
            if token_res['data']['session'] != []:
                user_id = token_res['data']['session'][0]['user_id']
                return {
                    'X-Hasura-Role': 'user',
                    'X-Hasura-User-Id': str(user_id)
                }
            else:
                return {}, 401
        else:
            return {"message": "From Webhook: cannot retrieve token"}, 500


api.add_resource(Signup, '/signup')
api.add_resource(Login, '/login')
api.add_resource(Webhook, '/webhook')

if __name__ == "__main__":
    print("Starting server...")
    app.run(debug = True)
