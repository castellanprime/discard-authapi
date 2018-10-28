import datetime, sys, json

from flask import (
 	Blueprint, 
 	request, 
	make_response, 
	jsonify
)
from flask.views import MethodView
from authApi.api import (
	flask_bcrypt, 
	db
)
from authApi.api.models.user import UserModel
from authApi.api.models.blacklist import BlackListTokenModel
from authApi.api.utils.tokenutils import (
	token_required, 
	get_token,
	validate_token,
	create_blacklisted_token,
	validate_request_args
)
from authApi.api.utils.exceptions import (
	OtherError,
	UnauthorizedAccess,
	BlacklistedToken,
	ExpiredToken,
	InvalidToken,
	UserAlreadyExist,
	UserDoesNotExist
)

auth_blueprint = Blueprint('auth', __name__)

class RegisterRoute(MethodView):
	"""User registration resource"""
	decorators = [validate_request_args('username', 'password')]

	def post(self):
		json_object = request.get_json()
		user = UserModel.query.filter_by(username=json_object.get('username')).first()
		if user:
			response_obj = dict(
				status='Fail',
				message=str(UserAlreadyExist()),
				error=UserAlreadyExist.__name__
			)
			return make_response(jsonify(response_obj), 500)
		user = UserModel(
			username=json_object.get('username'),
			password=json_object.get('password')
		)
		if json_object.get('admin'):
			user.admin = json_object.get('admin')
		if json_object.get('anonymous'):
			user.anonymous = json_object.get('anonymous')
		access_token, refresh_token, refresh_token_id = user.encode_auth_tokens(user.username)
		user.token_id = refresh_token_id
		db.session.add(user)
		db.session.commit()
		response_obj = dict(
			status='Success',
			message='Successfully registered',
			access_token=access_token.decode(),
			refresh_token=refresh_token.decode()
		)
		return make_response(jsonify(response_obj), 201)

class LoginRoute(MethodView):
	"""User login resource"""
	decorators = [validate_request_args('username', 'password')]

	def post(self):
		json_object = request.get_json()
		user = UserModel.query.filter_by(username=json_object.get('username')).first()
		if user and user.check_password(json_object.get('password')):
			access_token, refresh_token, refresh_token_id = user.encode_auth_tokens(user.username)
			user.token_id = refresh_token_id
			db.session.commit()
			response_obj = dict(
				status='Success',
				message='Successfully logged in',
				access_token=access_token.decode(),
				refresh_token=refresh_token.decode()
			)
			return make_response(jsonify(response_obj), 200)
		else:
			response_obj = dict(
				status='Fail',
				message=str(UserDoesNotExist()),
				error=UserDoesNotExist.__name__
			)
		return make_response(jsonify(response_obj), 500)


class UserRoute(MethodView):
	"""User resource"""
	decorators = [token_required, validate_token]

	def get(self):
		token = get_token()
		payload = UserModel.decode_refresh_token(token)
		payload_dict = json.loads(payload)
		user = UserModel.query.filter_by(public_id=payload_dict.get('name')).first()
		response_obj = dict(
			status='Success',
			data=dict(
				username=user.username,
				registered_on=user.registered_on,
				admin=user.admin,
				anonymous=user.anonymous
			)
		)
		return make_response(jsonify(response_obj), 200)

	def post(self):
		token = get_token()
		post_data = request.get_json()
		if any(['typeOfChange' not in post_data.keys(), 'message' not in post_data.keys()]):
			response_obj = dict(
				status='Fail',
				message='You are missing either "typeOfChange" or "message" or both',
				error=OtherError.__name__
			)
			return make_response(jsonify(response_obj), 500)

		payload = UserModel.decode_refresh_token(token)
		payload_dict = json.loads(payload)
		user = UserModel.query.filter_by(public_id=payload_dict.get('name')).first()
    
		if post_data.get('typeOfChange') == 'password':
			user.change_password(post_data.get('message'))
		if post_data.get('typeOfChange') == 'username':
			user.change_username(post_data.get('message'))
		if post_data.get('typeOfChange') == 'both':
			user.change_password(post_data.get('message').get('password'))
			user.change_username(post_data.get('message').get('username'))

		blacklisted_token = BlackListTokenModel(token_id=user.token_id)
		user.token_id = ''
		db.session.add(blacklisted_token)
		db.session.commit()

		message = ''
		if post_data.get('typeOfChange') == 'password':
			message = 'Changed your password'
		if post_data.get('typeOfChange') == 'username':
			message = 'Changed your username'
		if post_data.get('typeOfChange') == 'both':
			message = 'Changed your username and password'
		response_obj = dict(
			status='Success',
			message=message
		)
		return make_response(jsonify(response_obj), 200)

class UsersRoute(MethodView):
	"""Users resource"""
	decorators = [token_required, validate_token]
  
	def get(self):
		token = get_token()
		payload = UserModel.decode_refresh_token(token)
		payload_dict = json.loads(payload)
		if payload_dict.get('admin'):
			users = UserModel.query.all()
			users[:] = [(user.username, user.registered_on) for user in users]
			response_obj = dict(
				status='Success',
				message=users
			)
			return make_response(jsonify(response_obj), 200)
		else:
			response_obj = dict(
				status='Fail',
				message=str(UnauthorizedAccess()),
				error=UnauthorizedAccess.__name__
			)
			return make_response(jsonify(response_obj), 403)

class ReAuthRoute(MethodView):
	"""User Tokens regeneration resource"""
	decorators = [token_required]

	def post(self):
		token = get_token()
		try:
			payload = UserModel.decode_refresh_token(token)
			payload_dict = json.loads(payload)
			user = UserModel.query.filter_by(public_id=payload_dict.get('name')).first()
			access_token = user.encode_access_token(user.username)
			response_obj = dict(
				status='Success',
				message='Generated new access token',
				refresh_token_renewed=False,
				access_token=access_token.decode()
			)
			return make_response(jsonify(response_obj), 200)
		except ExpiredToken as e:
			payload = UserModel.decode_expired_token(token)
			payload_dict = json.loads(payload)
			user = UserModel.query.filter_by(public_id=payload_dict.get('name')).first()
			access_token, refresh_token, refresh_token_id = user.encode_auth_tokens(user.username)
			blacklisted_token = BlackListTokenModel(token_id=payload_dict.get('token_id'))
			user.token_id = refresh_token_id
			db.session.add(blacklisted_token)
			db.session.commit()

			response_obj = dict(
				status='Success',
				message='Generated new refresh and access tokens',
				refresh_token_renewed=True,
				access_token=access_token.decode(),
				refresh_token=refresh_token.decode()
			)
			return make_response(jsonify(response_obj), 200)
		except InvalidToken as err:
			blacklisted_token = create_blacklisted_token(err, token)
			db.session.add(blacklisted_token)
			db.session.commit()
			response_obj = dict(
				status='Fail',
				message=str(UnauthorizedAccess()),
				error=UnauthorizedAccess.__name__
			)
			return make_response(jsonify(response_obj), 403)
		except (BlacklistedToken, Exception) as err:
			error = None
			if isinstance(err, BlacklistedToken):
				error = BlacklistedToken.__name__
			else:
				error = OtherError.__name__
			response_obj = dict(
				status='Fail',
				message=str(err),
				error=error
			)
			return make_response(jsonify(response_obj), 500)

class ForcedLogoutRoute(MethodView):
	"""User forced logout resource"""
	decorators = [validate_request_args('public_id')]

	def post(self):
		payload = request.get_json()
		user = UserModel.query.filter_by(public_id=payload.get('public_id')).first()
		if user:
			blacklisted_token = BlackListTokenModel(token_id=user.token_id)
			user.token_id = ''
			db.session.add(user)
			db.session.commit()
			response_obj = dict(
				status='Success',
				message='User has been logged out'
			)
			return make_response(jsonify(response_obj), 200)
		else:
			response_obj = dict(
				status='Fail',
				message=str(UserDoesNotExist()),
				error=UserDoesNotExist.__name__
			)
			return make_response(jsonify(response_obj), 401)

class NormalLogoutRoute(MethodView):
	"""User normal logout resoure"""
	decorators = [token_required, validate_token]

	def post(self):
		token = get_token()
		payload = UserModel.decode_refresh_token(token)
		payload_dict = json.loads(payload)
		user = UserModel.query.filter_by(public_id=payload_dict.get('name')).first()
		blacklisted_token = BlackListTokenModel(token_id=user.token_id)
		user.token_id = ''
		if user.anonymous:
			db.session.delete(user)
		db.session.commit()
		response_obj = dict(
			status='Success',
			message='Successfully logged out'
		)
		return make_response(jsonify(response_obj), 200)

register_route = RegisterRoute.as_view('register_route')
login_route = LoginRoute.as_view('login_route') 
user_route = UserRoute.as_view('user_route')
users_route =  UsersRoute.as_view('users_route')
reauth_route = ReAuthRoute.as_view('reauth_route')
forcedlogout_route = ForcedLogoutRoute.as_view('forcedlogout_route')
normallogout_route = NormalLogoutRoute.as_view('normallogout_route')

auth_blueprint.add_url_rule(
	'/api/auth/register',
	view_func=register_route,
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
	methods=['GET', 'POST']
)

auth_blueprint.add_url_rule(
	'/api/auth/users',
	view_func=users_route,
	methods=['GET']
)

auth_blueprint.add_url_rule(
	'/api/auth/reauth',
	view_func=reauth_route,
	methods=['POST']
)

auth_blueprint.add_url_rule(
	'/api/auth/forcedlogout',
	view_func=forcedlogout_route,
	methods=['POST']
)

auth_blueprint.add_url_rule(
	'/api/auth/logout',
	view_func=normallogout_route,
	methods=['POST']
)
