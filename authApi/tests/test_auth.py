import time
import json
import unittest

from authApi.api import db
from authApi.api.models.user import UserModel
from authApi.api.models.blacklist import BlackListTokenModel
from authApi.tests.base import BaseTestCase

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

def get_user_status_malformed_token(self, token):
	return self.client.get(
		'/api/auth/me',
		headers=dict(
			Authorization='Bearer' + json.loads(
				token.data.decode()
			)['refresh_token']
		),
		content_type='application/json'
	)

def get_user_status_no_token(self):
	return self.client.get(
		'/api/auth/me',
		headers=dict(
			Authorization=''
		),
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

class TestAuthBlueprint(BaseTestCase):
	
	def test_registration(self):
		"""Test for user registration"""
		with self.client:
			response = register_user(self, 'fmaketouser', '123456')
			data = json.loads(response.data.decode())
			self.assertTrue(data.get('status') == 'Success')
			self.assertTrue(data.get('message') == 'Successfully registered')
			self.assertTrue(data.get('access_token'))
			self.assertTrue(data.get('refresh_token'))
			self.assertTrue(response.content_type == 'application/json')
			self.assertEqual(response.status_code, 201)

	def test_registration_with_already_registered_user(self):
		""" Test registration with already registered username"""
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
			self.assertTrue(data.get('message') == 'User always exists. Please Log in')
			self.assertEqual(response.status_code, 401)

	def test_login(self):
		"""Test for user login"""
		with self.client:
			response_register = register_user(self, 'fmaketouser1', '789012')
			data_register = json.loads(response_register.data.decode())
			self.assertTrue(data_register.get('status') == 'Success')
			self.assertTrue(data_register.get('message') == 'Successfully registered')
			self.assertTrue(data_register.get('access_token'))
			self.assertTrue(data_register.get('refresh_token'))
			self.assertTrue(response_register.content_type == 'application/json')
			self.assertEqual(response_register.status_code, 201)

			response = login_user(self, 'fmaketouser1', '789012')
			data = json.loads(response.data.decode())
			self.assertTrue(data.get('status') == 'Success')
			self.assertTrue(data.get('message') == 'Successfully logged in')
			self.assertTrue(data.get('access_token'))
			self.assertTrue(data.get('refresh_token'))
			self.assertTrue(response.content_type == 'application/json')
			self.assertEqual(response.status_code, 200) 

	def test_non_registered_user_login(self):
		""" Test for login of non-registered user"""
		with self.client:
			response = login_user(self, 'fmaketouser2', '1a2e3r')
			data = json.loads(response.data.decode())
			self.assertTrue(data.get('status') == 'Fail')
			self.assertTrue(data.get('message') == 'User does not exist')
			self.assertTrue(response.content_type == 'application/json')
			self.assertEqual(response.status_code, 404)

	def test_normal_user_status(self):
		"""Test user status"""
		with self.client:
			response = register_user(self, 'fmaketouser', '123456');
			resp = get_user_status(self, response)
			data = json.loads(resp.data.decode())
			self.assertTrue(data.get('status') == 'Success')
			self.assertTrue(data.get('data') is not None)
			self.assertTrue(data.get('data')['username'] == 'fmaketouser')
			self.assertTrue(data.get('data')['admin'] is False)
			self.assertTrue(data.get('data')['anonymous'] is False)
			self.assertTrue(resp.status_code, 200)

	def test_admin_user_status(self):
		"""Test admin user status"""
		with self.client:
			response = register_user(self, username='fmaketouser', password='123456', admin=True)
			resp = get_user_status(self, response)
			data = json.loads(resp.data.decode())
			self.assertTrue(data.get('status') == 'Success')
			self.assertTrue(data.get('data') is not None)
			self.assertTrue(data.get('data')['username'] == 'fmaketouser')
			self.assertTrue(data.get('data')['admin'] is True)
			self.assertTrue(data.get('data')['anonymous'] is False)
			self.assertTrue(resp.status_code, 200)

	def test_anonymous_user_status(self):
		"""Test anonymous user status"""
		with self.client:
			response = register_user(self, 'fmaketouser', '123456', anonymous=True)
			resp = get_user_status(self, response)
			data = json.loads(resp.data.decode())
			self.assertTrue(data.get('status') == 'Success')
			self.assertTrue(data.get('data') is not None)
			self.assertTrue(data.get('data')['username'] == 'fmaketouser')
			self.assertTrue(data.get('data')['admin'] is False)
			self.assertTrue(data.get('data')['anonymous'] is True)
			self.assertTrue(resp.status_code, 200)

	def test_user_status_malformed_bearer_token(self):
		""" Test for user status with malformed bearer token"""
		with self.client:
			response = register_user(self, 'fmaketouser', '123456', admin=True)
			resp = get_user_status_malformed_token(self, response)
			data = json.loads(resp.data.decode())
			self.assertTrue(data.get('status') == 'Fail')
			self.assertTrue(data.get('message') == 'Bearer message malformed')
			self.assertEqual(resp.status_code, 401)

	def test_user_status_no_token(self):
		""" Test for user status with no token"""
		with self.client:
			response = register_user(self, 'fmaketouser', '123456')
			resp = get_user_status_no_token(self)
			data = json.loads(resp.data.decode())
			self.assertTrue(data.get('status') == 'Fail')
			self.assertTrue(data.get('message') == 'Provide a valid auth token')
			self.assertEqual(resp.status_code, 401)

	def test_get_users_status(self):
		""" Test for getting all users in the system"""
		with self.client:
			response1 = register_user(self, 'fmaketouser', '123456')
			response2 = register_user(self, 'fmaketouser1', '789012', admin=True)
			response3 = register_user(self, 'fmaketouser2', 'we234q')
			
			resp = get_all_users(self, response2)
			data = json.loads(resp.data.decode())
			self.assertTrue(data.get('status') == 'Success')
			self.assertTrue(data.get('data') is not None)
			self.assertTrue(isinstance(data.get('data'), list))
			self.assertTrue(len(data.get('data')) == 3)
			self.assertTrue(resp.status_code, 200)

			resp1 = get_all_users(self, response1)
			data = json.loads(resp1.data.decode())
			self.assertTrue(data.get('status') == 'Fail')
			self.assertTrue(data.get('message') == 'Unauthorized since you are not an admin')
			self.assertTrue(response1.status_code, 401) 

			resp2 = self.client.get(
				'/api/auth/users',
				headers=dict(
					Authorization=''
				)
			)
			data = json.loads(resp2.data.decode())
			self.assertTrue(data.get('status') == 'Fail')
			self.assertTrue(data.get('message') == 'Provide a valid auth token')
			self.assertTrue(resp2.status_code, 401)

if __name__ == '__main__':
	unittest.main()
