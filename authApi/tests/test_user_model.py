import unittest
import jwt
import datetime
import json

from authApi.api import db
from authApi.api.config import key
from authApi.api.models.user import UserModel
from authApi.tests.base import BaseTestCase

class TestUserModel(BaseTestCase):
	def test_encode_auth_tokens(self):
		user = UserModel(
			username='Username1',
			password='Password1'
		)
		db.session.add(user)
		db.session.commit()
		access_token, refresh_token, refresh_token_id = user.encode_auth_tokens(user.username)
		self.assertTrue(isinstance(access_token, bytes))
		self.assertTrue(isinstance(refresh_token, bytes))
		self.assertTrue(isinstance(refresh_token_id, str))

	def test_decode_refresh_token(self):
		user = UserModel(
			username='Username2',
			password='Password2'
		)
		db.session.add(user)
		db.session.commit()
		access_token, refresh_token, refresh_token_id = user.encode_auth_tokens(user.username)
		self.assertTrue(isinstance(access_token, bytes))
		self.assertTrue(isinstance(refresh_token, bytes))
		self.assertTrue(isinstance(refresh_token_id, str))

		response = UserModel.decode_refresh_token(refresh_token)
		self.assertTrue(isinstance(response, str))

	def test_encode_access_token(self):
		username = 'Username2'
		user = UserModel(
			username='Username2',
			password='Password2'
		)
		db.session.add(user)
		db.session.commit()

		access_token = user.encode_access_token(username)
		self.assertTrue(isinstance(access_token, bytes))
		payload = jwt.decode(access_token, key)
		self.assertTrue(payload.get('sub') == username)

	def test_decode_expired_token(self):
		user = UserModel(
			username='Username2',
			password='Password2'
		)
		db.session.add(user)
		db.session.commit()
		_, refresh_token, refresh_token_id = user.encode_auth_tokens(user.username)
		self.assertTrue(isinstance(refresh_token, bytes))
		
		payload = jwt.decode(refresh_token, key)
		payload['exp'] = datetime.datetime.utcnow() - datetime.timedelta(minutes=32)
		token = jwt.encode(payload, key, algorithm='HS256')
		response = UserModel.decode_expired_token(token)
		resp = json.loads(response)
		self.assertTrue(resp.get('name') == payload.get('sub'))
		self.assertTrue(resp.get('token_id') == payload.get('jti'))

	def test_check_password(self):
		user = UserModel(
			username='Username2',
			password='Password2'
		)
		db.session.add(user)
		db.session.commit()
		self.assertTrue(user.check_password('Password2'))
		self.assertFalse(user.check_password('Pass23word'))

	def test_change_password(self):
		user = UserModel(
			username='Username2',
			password='Password2'
		)
		db.session.add(user)
		db.session.commit()
		self.assertTrue(user.check_password('Password2'))
		user.change_password('Password3')
		self.assertTrue(user.check_password('Password3'))
		self.assertTrue(user.updated_by == user.public_id)
		user.change_password('Password4', principal='SYSTEM')
		self.assertTrue(user.check_password('Password4'))
		self.assertTrue(user.updated_by == 'SYSTEM')

	def test_change_username(self):
		user = UserModel(
			username='Username2',
			password='Password2'
		)
		db.session.add(user)
		db.session.commit()
		self.assertTrue(user.username == 'Username2')
		user.change_username('Username3')
		self.assertTrue(user.username == 'Username3')
		self.assertTrue(user.updated_by == user.public_id)
		user.change_username('Username4', principal='SYSTEM')
		self.assertTrue(user.username == 'Username4')
		self.assertTrue(user.updated_by == 'SYSTEM')

if __name__ == '__main__':
	unittest.main()
