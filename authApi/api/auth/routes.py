import datetime
import sys
import json
from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView

from authApi.api import flask_bcrypt, db
from authApi.api.models.user import UserModel
from authApi.api.models.blacklist import BlackListTokenModel

auth_blueprint = Blueprint('auth', __name__)

class RegisterRoute(MethodView):
	"""User Registration Resource"""
	def post(self):
		post_data = request.get_json()
		user = UserModel.query.filter_by(username=post_data.get('username')).first()
		if user is None:
			try:
				if post_data.get('admin'):
					user = UserModel(
						username=post_data.get('username'),
						password=post_data.get('password'),
						admin=post_data.get('admin')
					)
				elif post_data.get('anonymous'):
					user = UserModel(
						username=post_data.get('username'),
						password=post_data.get('password'),
						anonymous=post_data.get('anonymous')
					)
				else:
					user = UserModel(
						username=post_data.get('username'),
						password=post_data.get('password')
					)
				print('db:', db.session)
				access_token, refresh_token, refresh_token_id = user.encode_auth_tokens(user.username)
				print('Tokens: ', access_token, ': ', refresh_token)
				user.token_id = refresh_token_id
				print('User: ', user)
				db.session.add(user)
				db.session.commit()
				response = {
					'status':'Success',
					'message':'Successfully registered',
					'access_token':access_token.decode(),
					'refresh_token': refresh_token.decode()
				}
				return make_response(jsonify(response)), 201
			except Exception as e:
				response = {
					'status':'Fail',
					'message':'Some error occured.Please try again'
				}
				return make_response(jsonify(response)), 500
		else:
			response = {
				'status':'Fail',
				'message':'User always exists. Please Log in'
			}
			return make_response(jsonify(response)), 401

class LoginRoute(MethodView):
	"""User login resource"""
	def post(self):
		post_data = request.get_json()
		try:
			user = UserModel.query.filter_by(username=post_data.get('username')).first()
			if user and flask_bcrypt.check_password_hash(user.password_hash, post_data.get('password')):
				access_token, refresh_token, refresh_token_id = user.encode_auth_tokens(user.username)
				if access_token and refresh_token and refresh_token_id:
					user.token_id = refresh_token_id
					db.session.commit()
					response = {
						'status': 'Success',
						'message': 'Successfully logged in',
						'access_token': access_token.decode(),
						'refresh_token': refresh_token.decode()
					}
					return make_response(jsonify(response)), 200
			else:
				response = {
					'status': 'Fail',
					'message': 'User does not exist'
				}
				return make_response(jsonify(response)), 404
		except Exception as e:
			print(e)
			response = {
				'status': 'Fail',
				'message': 'Try again'
			}
			return make_response(jsonify(response)), 500

class UserRoute(MethodView):
	"""User resource"""
	def get(self):
		auth_header = request.headers.get('Authorization')
		if auth_header:
			try:
				auth_token = auth_header.split(' ')[1]
			except IndexError:
				response = {
					'status': 'Fail',
					'message': 'Bearer message malformed'
				}
				return make_response(jsonify(response)), 401
		else:
			auth_token = ''
		if auth_token:	# an empty string will not enter this loop
			resp = UserModel.decode_refresh_token(auth_token)
			try:
				response = json.loads(resp)
				user = UserModel.query.filter_by(username=response['name']).first()
				res_object = {
					'status': 'Success',
					'data': {
						'username': user.username,
						'registered_on': user.registered_on,
						'admin': user.admin,
						'anonymous': user.anonymous
					}
				}
				return make_response(jsonify(res_object)), 200
			except json.decoder.JSONDecodeError:
				print(e)
				responseObject = {
					'status': 'Fail',
					'message': resp
				}
				return make_response(jsonify(responseObject)), 401
		else:
			responseObject = {
				'status': 'Fail',
				'message': 'Provide a valid auth token'
			}
			return make_response(jsonify(responseObject)), 401

class UsersRoute(MethodView):
	"""User resource for admin"""
	def get(self):
		auth_header = request.headers.get('Authorization')
		if auth_header:
			try:
				auth_token = auth_header.split(' ')[1]
			except IndexError:
				response = {
					'status':'Fail',
					'message': 'Bearer message malformed'
				}
				return make_response(jsonify(response)), 401
		else:
			auth_token = ''
		if auth_token:
			resp = UserModel.decode_refresh_token(auth_token)
			try:
				response = json.loads(resp)
				if response['admin']:
					users = UserModel.query.all()
					users[:] = [(user.username, user.registered_on) for user in users]
					responseObject = {
						'status': 'Success',
						'data': users
					}
					return make_response(jsonify(responseObject)), 200
				else:
					responseObject = {
						'status': 'Fail',
						'message': 'Unauthorized since you are not an admin'
					}
					return make_response(jsonify(responseObject)), 401
			except json.decoder.JSONDecodeError:
				print(e)
				responseObject = {
					'status': 'Fail',
					'message': 'resp'
				}
				return make_response(jsonify(responseObject)), 401
		else:
			responseObject = {
				'status': 'Fail',
				'message':'Provide a valid auth token'
			}
			return make_response(jsonify(responseObject)), 401

## define API resources
registration_route = RegisterRoute.as_view('register_route')
login_route = LoginRoute.as_view('login_route')
user_route = UserRoute.as_view('user_route')
users_route =  UsersRoute.as_view('users_route')

# add rules for API endpoints
auth_blueprint.add_url_rule(
	'/api/auth/register',
	view_func=registration_route,
	methods=['POST']
)

auth_blueprint.add_url_rule(
	'/api/auth/login',
	view_func=login_route,
	methods=['POST']
)

auth_blueprint.add_url_rule(
	'/api/auth/me',
	view_func=user_route,
	methods=['GET']
)

auth_blueprint.add_url_rule(
	'/api/auth/users',
	view_func=users_route,
	methods=['GET']
)
