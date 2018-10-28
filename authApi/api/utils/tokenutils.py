# Decorators

import json
from authApi.api.utils.exceptions import (
	MalformedBearer,
	InvalidToken,
	BlacklistedToken,
	ExpiredToken,
	UnauthorizedAccess,
	OtherError
)
from authApi.api import db
from authApi.api.models.user import UserModel
from authApi.api.models.blacklist import BlackListTokenModel
from flask import request, make_response, jsonify
from functools import wraps

def token_required(func):
	@wraps(func)
	def decorated(*args, **kwargs):
		auth_header = request.headers.get('Authorization')
		if auth_header:
			try: 
				auth_token = auth_header.split(' ')[1]
			except IndexError:
				response_obj = dict(
					status='Fail',
					message=str(MalformedBearer()),
					error=MalformedBearer.__name__
				)
				return make_response(jsonify(response_obj), 400)
		else:
			auth_token = ''
		if auth_token:
			return func(*args, **kwargs)
		else:
			response_obj = dict(
				status='Fail',
				message=str(InvalidToken()),
				error=InvalidToken.__name__
			)
			return make_response(jsonify(response_obj), 401)
	return decorated

def validate_token(func):
	@wraps(func)
	def decorated(*args, **kwargs):
		token = get_token()
		try:
			payload = UserModel.decode_refresh_token(token)
			return func(*args, **kwargs)
		except (InvalidToken, ExpiredToken) as e:
			blacklisted_token = create_blacklisted_token(e, token)
			db.session.add(blacklisted_token)
			db.session.commit()
			response_obj = dict(
				status='Fail',
				message=str(UnauthorizedAccess()),
				error=UnauthorizedAccess.__name__
			)
			return make_response(jsonify(response_obj), 403)
		except (BlacklistedToken, Exception) as err:
			if isinstance(err, BlacklistedToken):
				response_obj = dict(
					status='Fail',
					message=str(BlacklistedToken()),
					error=BlacklistedToken.__name__
				)
				return make_response(jsonify(response_obj), 403)
			response_obj = dict(
				status='Fail',
				message=str(err),
				error=OtherError.__name__
			)
			return make_response(jsonify(response_obj), 500)
	return decorated

def validate_request_args(*expected_args):
	def decorated_validate_request_args(func):
		@wraps(func)
		def wrapper_validate_request_args(*args, **kwargs):
			json_object = json.loads(request.get_json()) if isinstance(request.get_json(), str) else request.get_json() 
			for expected_arg in expected_args:
				if any([expected_arg not in json_object, 
					json_object.get(expected_arg) is None, 
				]):
					message = 'You are missing this parameter: ' + expected_arg
					response_obj = dict(
						status='Fail',
						message=message,
						error=OtherError.__name__ 
					)
					return make_response(jsonify(response_obj), 400)
			return func(*args, **kwargs)
		return wrapper_validate_request_args
	return decorated_validate_request_args 

def get_token():
	auth_header = request.headers.get('Authorization')
	auth_token = auth_header.split(' ')[1]
	return auth_token

def create_blacklisted_token(e, token):
	blacklisted_token = None
	if isinstance(e, ExpiredToken):
		payload = UserModel.decode_expired_token(token)
		payload_dict = json.loads(payload)
		blacklisted_token = BlackListTokenModel(token_id=payload_dict.get('token_id'))
	elif isinstance(e, InvalidToken):
		blacklisted_token = BlackListTokenModel(token=token)
	return blacklisted_token
