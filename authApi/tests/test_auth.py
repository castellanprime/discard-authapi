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
			anonymous=anonmyous
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
		)
	)

def get_user_status_malformed_token(self, token):
	return self.client.get(
		'/api/auth/me',
		headers=dict(
			Authorization='Bearer' + json.loads(
				token.data.decode()
			)['refresh_token']
		)
	)

class TestAuthBlueprint(BaseTestCase):
	
	def test_registration(self):
		"""Test for user registration"""
		with self.client:
			response = register_user(self, 'fmaketouser', '123456')
			data = json.loads(response.data.decode())
			print(data)
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
			print(data)
			self.assertTrue(data.get('status') == 'Fail')
			self.assertTrue(data.get('message') == 'User always exists. Please Log in')
			self.assertEqual(response.status_code, 401)

	def test_login(self):
		"""Test for user login"""
		with self.client:
			response_register = register_user(self, 'fmaketouser1', '789012')
			data_register = json.loads(response_register.data.decode())
			print(data_register)
			self.assertTrue(data_register.get('status') == 'Success')
			self.assertTrue(data_register.get('message') == 'Successfully registered')
			self.assertTrue(data_register.get('access_token'))
			self.assertTrue(data_register.get('refresh_token'))
			self.assertTrue(response_register.content_type == 'application/json')
			self.assertEqual(response_register.status_code, 201)

			response = login_user(self, 'fmaketouser1', '789012')
			data = json.loads(response.data.decode())
			print(data)
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
			print(response)
			self.assertTrue(data.get('status') == 'Fail')
			self.assertTrue(data.get('message') == 'User does not exist')
			self.assertTrue(response.content_type == 'application/json')
			self.assertEqual(response.status_code, 404)

	def test_normal_user_status(self):
		"""Test user status"""
		with self.client:
			response = register_user(self, 'fmaketouser', '123456');
			resp = get_user_status(response)
			data = json.loads(resp.data.decode())
			print(data)
			self.assertTrue(data.get('status') == 'Sucess')
			self.assertTrue(data.get('data') is not None)
			self.assertTrue(data.get('data')['username'] == 'fmaketouser')
			self.assertTrue(data.get('data')['admin'] is 'false')
			self.assertTrue(data.get('data')['anonymous'] is 'false')
			self.assertTrue(resp.status_code, 200)

	def test_admin_user_status(self):
		"""Test admin user status"""
		with self.client:
			response = register_user(self, 'fmaketouser', '123456', admin=True)
			resp = get_user_status(response)
			data = json.loads(resp.data.decode())
			print(data)
			self.assertTrue(data.get('status') == 'Success')
			self.assertTrue(data.get('data') is not None)
			self.assertTrue(data.get('data')['username'] == 'fmaketouser')
			self.assertTrue(data.get('data')['admin'] is 'true')
			self.assertTrue(data.get('data')['anonymous'] is 'false')
			self.assertTrue(resp.status_code, 200)

	def test_anonymous_user_status(self):
		"""Test anonymous user status"""
		with self.client:
			response = register_user(self, 'fmaketouser', '123456', admin=True)
			resp = get_user_status(response)
			data = json.loads(resp.data.decode())
			print(data)
			self.assertTrue(data.get('status') == 'Success')
			self.assertTrue(data.get('data') is not None)
			self.assertTrue(data.get('data')['username'] == 'fmaketouser')
			self.assertTrue(data.get('data')['admin'] is 'false')
			self.assertTrue(data.get('data')['anonymous'] is 'true')
			self.assertTrue(resp.status_code, 200)

	def test_user_status_malformed_bearer_token(self):
		""" Test for user status with malformed bearer token"""
		with self.client:
			response = register_user(self, 'fmaketouser', '123456', admin=True)
			resp = get_user_status_malformed_token(response)
			data = json.loads(resp.data.decode())
			self.assertTrue(data['status'] == 'Fail')
            self.assertTrue(data['message'] == 'Bearer token malformed.')
			self.assertEqual(response.status_code, 401)

if __name__ == '__main__':
	unittest.main()
