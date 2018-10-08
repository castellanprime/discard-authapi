import time
import json
import unittest

from authApi.api import db
from authApi.api.models.user import UserModel
from authApi.api.models.blacklist import BlackListTokenModel
from authApi.tests.base import BaseTestCase

def register_user(self, username, password):
	return self.client.post(
		'/api/auth/register',
		data=json.dumps(dict(
			username=username,
			password=password
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
		""" Test for login of non-regsitered user"""
		with self.client:
			response = login_user(self, 'fmaketouser2', '1a2e3r')
			data = json.loads(response.data.decode())
			print(response)
			self.assertTrue(data.get('status') == 'Fail')
			self.assertTrue(data.get('message') == 'User does not exist')
			self.assertTrue(response.content_type == 'application/json')
			self.assertEqual(response.status_code, 404)


if __name__ == '__main__':
	unittest.main()
