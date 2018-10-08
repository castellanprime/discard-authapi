import unittest

from authApi.api import db
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

	def test_decode_register_token(self):
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

if __name__ == '__main__':
	unittest.main()
