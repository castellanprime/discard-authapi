import time
import json
import unittest
import jwt
import datetime

from unittest import mock
from authApi.api import db
from authApi.api.models.user import UserModel
from authApi.api.models.blacklist import BlackListTokenModel
from authApi.tests.base import BaseTestCase
from authApi.api.config import key
from authApi.api.utils.exceptions import (
	UserAlreadyExist,
	UserDoesNotExist,
	UnauthorizedAccess,
	OtherError,
	ExpiredToken,
	InvalidToken,
	BlacklistedToken
)
import authApi.api.auth.routes

def register_user(self, username, password, admin=False, anonymous=False): 
	return self.client.post(
		'/api/auth/register',
		data=json.dumps(dict(
			username=username,
			password=password,
			admin=admin,
			anonymous=anonymous
		)),
		content_type='application/json'
	)

def login_user(self, username, password):
	return self.client.post(
		'/api/auth/login',
		data=json.dumps(dict(
			username=username,
			password=password
		)),
		content_type='application/json'
	)

def get_user_status(self, token):
	return self.client.get(
		'/api/auth/me',
		headers=dict(
			Authorization='Bearer ' + json.loads(
				token.data.decode()
			)['refresh_token']
		),
		content_type='application/json'
	)

def change_user_attr(self, token, username=None, password=None):
	if username and password is None:
		return self.client.post(
			'/api/auth/me',
			headers=dict(
				Authorization='Bearer ' + json.loads(
					token.data.decode()
				)['refresh_token']
			),
			data=json.dumps(dict(
				typeOfChange='username',
				message=username
			)),
			content_type='application/json'
		)
	elif password and username is None:
		return self.client.post(
			'/api/auth/me',
			headers=dict(
				Authorization='Bearer ' + json.loads(
					token.data.decode()
				)['refresh_token']
			),
			data=json.dumps(dict(
				typeOfChange='password',
				message=password
			)),
			content_type='application/json'
		)
	elif password and username:
		return self.client.post(
			'/api/auth/me',
			headers=dict(
				Authorization='Bearer ' + json.loads(
					token.data.decode()
				)['refresh_token']
			),
			data=json.dumps(dict(
				typeOfChange='both',
				message=dict(
					username=username,
					password=password
				)
			)),
			content_type='application/json'
		)
	elif password is None and username is None:
		return self.client.post(
			'/api/auth/me',
			headers=dict(
				Authorization='Bearer ' + json.loads(
					token.data.decode()
				)['refresh_token']
			),
			data=json.dumps(dict()),
			content_type='application/json'
		)

def get_all_users(self, token):
	return self.client.get(
		'/api/auth/users',
		headers=dict(
			Authorization='Bearer ' + json.loads(
				token.data.decode()
			)['refresh_token']
		),
		content_type='application/json'
	)

def get_refreshed_token(self, token, isOrdinaryToken=False):
	if isOrdinaryToken:
		return self.client.post(
			'/api/auth/reauth',
			headers=dict(Authorization='Bearer ' + token),
			content_type='application/json'
		)
	return self.client.post(
		'/api/auth/reauth',
		headers=dict(
			Authorization='Bearer ' + json.loads(
				token.data.decode()
			)['refresh_token']
		),
		content_type='application/json'
	)

def make_app_logout(self, public_id):
	return self.client.post(
		'/api/auth/forcedlogout',
		json=dict(public_id=public_id),
		content_type='application/json'
	)

def logout_user(self, token):
	return self.client.post(
		'/api/auth/logout',
		headers=dict(
			Authorization='Bearer ' + json.loads(
				token.data.decode()
			)['refresh_token']
		),
		content_type='application/json'
	)

class TestAuthBlueprint(BaseTestCase):
	
	def test_registration(self):
		with self.client:
			response = register_user(self, 'fmaketouser', '123456')
			data = json.loads(response.data.decode())
			self.assertTrue(data.get('status') == 'Success')
			self.assertTrue(data.get('message') == 'Successfully registered')
			self.assertTrue(data.get('access_token'))
			self.assertTrue(data.get('refresh_token'))
			self.assertEqual(response.status_code, 201)

	def test_registration_with_already_registered_user(self):
		user = UserModel(
			username='fmaketouser',
			password='test'
		)
		db.session.add(user)
		db.session.commit()
		with self.client:
			response = register_user(self, 'fmaketouser', '123456')
			data = json.loads(response.data.decode())
			self.assertTrue(data.get('status') == 'Fail')
			self.assertTrue(data.get('message') == str(UserAlreadyExist()))
			self.assertTrue(data.get('error') == UserAlreadyExist.__name__)
			self.assertEqual(response.status_code, 500)

	def test_login(self):
		with self.client:
			response_register = register_user(self, 'fmaketouser1', '789012')
			data_register = json.loads(response_register.data.decode())
			self.assertTrue(data_register.get('status') == 'Success')
			self.assertTrue(data_register.get('message') == 'Successfully registered')
			self.assertTrue(data_register.get('access_token'))
			self.assertTrue(data_register.get('refresh_token'))
			self.assertEqual(response_register.status_code, 201)

			response = login_user(self, 'fmaketouser1', '789012')
			data = json.loads(response.data.decode())
			self.assertTrue(data.get('status') == 'Success')
			self.assertTrue(data.get('message') == 'Successfully logged in')
			self.assertTrue(data.get('access_token'))
			self.assertTrue(data.get('refresh_token'))
			self.assertEqual(response.status_code, 200)

	def test_non_registered_user_login(self):
		with self.client:
			response = login_user(self, 'fmaketouser2', '1a2e3r')
			data = json.loads(response.data.decode())
			self.assertTrue(data.get('status') == 'Fail')
			self.assertTrue(data.get('message') == 'User does not exist')
			self.assertEqual(response.status_code, 500)

	def test_normal_user_status(self):
 		with self.client:
 			response = register_user(self, 'fmaketouser', '123456')
 			resp = get_user_status(self, response)
 			data = json.loads(resp.data.decode())
 			self.assertTrue(data.get('status') == 'Success')
 			self.assertTrue(data.get('data') is not None)
 			self.assertTrue(data.get('data').get('username') == 'fmaketouser')
 			self.assertTrue(data.get('data').get('admin') is False)
 			self.assertTrue(data.get('data').get('anonymous') is False)
 			self.assertEqual(resp.status_code, 200)

	def test_admin_user_status(self):
		with self.client:
			response = register_user(self, username='fmaketouser', password='123456', admin=True)
			resp = get_user_status(self, response)
			data = json.loads(resp.data.decode())
			self.assertTrue(data.get('status') == 'Success')
			self.assertTrue(data.get('data') is not None)
			self.assertTrue(data.get('data').get('username') == 'fmaketouser')
			self.assertTrue(data.get('data').get('admin') is True)
			self.assertTrue(data.get('data').get('anonymous') is False)
			self.assertEqual(resp.status_code, 200)

	def test_anonymous_user_status(self):
		with self.client:
			response = register_user(self, 'fmaketouser', '123456', anonymous=True)
			resp = get_user_status(self, response)
			data = json.loads(resp.data.decode())
			self.assertTrue(data.get('status') == 'Success')
			self.assertTrue(data.get('data') is not None)
			self.assertTrue(data.get('data').get('username') == 'fmaketouser')
			self.assertTrue(data.get('data').get('admin') is False)
			self.assertTrue(data.get('data').get('anonymous') is True)
			self.assertEqual(resp.status_code, 200)
	
	def test_user_status_change_username_or_password(self):
		with self.client:
			response = register_user(self, 'fmaketouser', '123456')
			resp = change_user_attr(self, response, username='fmaketouser1')
			data = json.loads(resp.data.decode())
			self.assertTrue(data.get('status') == 'Success')
			self.assertTrue(data.get('message') == 'Changed your username')
			self.assertEqual(resp.status_code, 200)

			response = login_user(self, 'fmaketouser1', '123456')
			resp = change_user_attr(self, response, password='123890')
			data = json.loads(resp.data.decode())
			self.assertTrue(data.get('status') == 'Success')
			self.assertTrue(data.get('message') == 'Changed your password')
			self.assertEqual(resp.status_code, 200)

			response = login_user(self, 'fmaketouser1', '123890')
			resp = change_user_attr(self, response, username='fmaketouser2', password='098765')
			data = json.loads(resp.data.decode())
			self.assertTrue(data.get('status') == 'Success')
			self.assertTrue(data.get('message') == 'Changed your username and password')
			self.assertEqual(resp.status_code, 200)

			response = login_user(self, 'fmaketouser2', '098765')
			resp = change_user_attr(self, response)
			data = json.loads(resp.data.decode())
			self.assertTrue(data.get('status') == 'Fail')
			self.assertTrue(data.get('error') == OtherError.__name__)
			self.assertEqual(resp.status_code, 500)

	def test_get_users_status(self):
		with self.client:
			response1 = register_user(self, 'fmaketouser', '123456')
			response2 = register_user(self, 'fmaketouser1', '789012', admin=True)
			response3 = register_user(self, 'fmaketouser2', 'we234q')
			
			resp = get_all_users(self, response2)
			data = json.loads(resp.data.decode())
			self.assertTrue(data.get('status') == 'Success')
			self.assertTrue(data.get('message') is not None)
			self.assertTrue(isinstance(data.get('message'), list))
			self.assertTrue(len(data.get('message')) == 3)
			self.assertEqual(resp.status_code, 200)

			resp1 = get_all_users(self, response1)
			data = json.loads(resp1.data.decode())
			self.assertTrue(data.get('status') == 'Fail')
			self.assertTrue(data.get('message') == str(UnauthorizedAccess()))
			self.assertTrue(data.get('error') == UnauthorizedAccess.__name__)
			self.assertEqual(resp1.status_code, 403) 

	def test_refreshed_token_access(self):
		with self.client:
			response1 = register_user(self, 'fmaketouser', '123456')
			response = get_refreshed_token(self, response1)
			data = json.loads(response.data.decode())
			self.assertTrue(data.get('status') == 'Success')
			self.assertTrue(data.get('message') is not None)
			self.assertTrue(data.get('access_token'))
			self.assertFalse(data.get('refresh_token_renewed'))
			self.assertEqual(response.status_code, 200)
	
	def test_refreshed_tokens_access_and_refresh(self):
		with self.client:
			response = register_user(self, 'fmaketouser', '123456')
			data = json.loads(response.data.decode())
			refresh_token = data.get('refresh_token')
			payload = jwt.decode(refresh_token, key)
			payload['exp'] = datetime.datetime.utcnow() - datetime.timedelta(minutes=45)
			refresh_token = jwt.encode(payload, key, algorithm='HS256')
			with mock.patch('authApi.api.auth.routes.UserModel.decode_refresh_token') as decode_token:
				decode_token.side_effect = ExpiredToken()
				response = get_refreshed_token(self, refresh_token.decode(), isOrdinaryToken=True)
				data = json.loads(response.data.decode())
				self.assertTrue(data.get('status') == 'Success')
				self.assertTrue(data.get('message') is not None)
				self.assertTrue(data.get('refresh_token_renewed'))
				self.assertTrue(data.get('access_token'))
				self.assertTrue(data.get('refresh_token'))
				self.assertEqual(response.status_code, 200)

				decode_token.side_effect = InvalidToken()
				response = get_refreshed_token(self, refresh_token.decode(), isOrdinaryToken=True)
				data = json.loads(response.data.decode())
				self.assertTrue(data.get('status') == 'Fail')
				self.assertTrue(data.get('message') == str(UnauthorizedAccess()))
				self.assertTrue(data.get('error') == UnauthorizedAccess.__name__)
				self.assertEqual(response.status_code, 403)

				decode_token.side_effect = BlacklistedToken()
				response = get_refreshed_token(self, refresh_token.decode(), isOrdinaryToken=True)
				data = json.loads(response.data.decode())
				self.assertTrue(data.get('status') == 'Fail')
				self.assertTrue(data.get('message') == str(BlacklistedToken()))
				self.assertTrue(data.get('error') == BlacklistedToken.__name__)
				self.assertEqual(response.status_code, 500)

				decode_token.side_effect = Exception('TestException')
				response = get_refreshed_token(self, refresh_token.decode(), isOrdinaryToken=True)
				data = json.loads(response.data.decode())
				self.assertTrue(data.get('status') == 'Fail')
				self.assertTrue(data.get('message') == 'TestException')
				self.assertTrue(data.get('error') == OtherError.__name__)
				self.assertEqual(response.status_code, 500)

	def test_app_logout(self):
		with self.client:
			response = register_user(self, 'fmaketouser', '123456')
			data = json.loads(response.data.decode())
			payload = jwt.decode(data.get('refresh_token'), key)
			response = make_app_logout(self, payload.get('sub'))
			data = json.loads(response.data.decode())
			self.assertTrue(data.get('status') == 'Success')
			self.assertEqual(response.status_code, 200)

			response = make_app_logout(self, 'dsasa344')
			data = json.loads(response.data.decode())
			self.assertTrue(data.get('status') == 'Fail')
			self.assertTrue(data.get('message') == str(UserDoesNotExist()))
			self.assertTrue(data.get('error') == UserDoesNotExist.__name__)
			self.assertEqual(response.status_code, 401)

	def test_logout_user(self):
		with self.client:
			response = register_user(self, 'fmaketouser', '123456')
			response1 = logout_user(self, response)
			data = json.loads(response1.data.decode())
			self.assertTrue(data.get('status') == 'Success')
			self.assertTrue(data.get('message') == 'Successfully logged out')
			self.assertEqual(response1.status_code, 200)

			response2 = get_user_status(self, response)
			data = json.loads(response2.data.decode())
			self.assertTrue(data.get('status') == 'Success')
			self.assertTrue(data.get('data') is not None)
			self.assertTrue(data.get('data').get('username') == 'fmaketouser')
			self.assertTrue(data.get('data').get('admin') is False)
			self.assertTrue(data.get('data').get('anonymous') is False)
			self.assertTrue(response2.status_code, 200)

			response3 = register_user(self, 'fmaketouser1', '123456', anonymous=True)
			response = logout_user(self, response3)
			data = json.loads(response.data.decode())
			self.assertTrue(data.get('status') == 'Success')
			self.assertTrue(data.get('message') == 'Successfully logged out')
			self.assertEqual(response.status_code, 200)


if __name__ == '__main__':
	unittest.main()

