
import json
import unittest

from flask import request
from unittest import mock
from authApi.api import db
from authApi.api.models.user import UserModel
from authApi.api.models.blacklist import BlackListTokenModel
from authApi.tests.base import BaseTestCase
from authApi.api.config import key
from authApi.api.utils.tokenutils import (
	token_required,
	create_blacklisted_token,
	get_token,
	validate_request_args,
	validate_token
)
from authApi.api.utils.exceptions import (
	MalformedBearer,
	InvalidToken,
	ExpiredToken,
	BlacklistedToken,
	UnauthorizedAccess,
	OtherError
)


class TestUtils(BaseTestCase):

	def test_token_required(self):
		with mock.patch('authApi.api.utils.tokenutils.request') as mocked_request:
			mocked_request.headers = dict(Authorization='Bearer TestToken')
			@token_required
			def a():
				return 'test_function'
			result = a()
			self.assertTrue(result == 'test_function')
	
	def test_token_required_malformed_token(self):
		with mock.patch('authApi.api.utils.tokenutils.request') as mocked_request:
			mocked_request.headers = dict(Authorization='BearerTestToken')
			@token_required
			def a():
				return 'test_function'
			result = a()
			response = json.loads(result.data.decode())
			self.assertEqual(result.status_code, 400)
			self.assertTrue(response.get('status') == 'Fail')
			self.assertTrue(response.get('message') == str(MalformedBearer()))
			self.assertTrue(response.get('error') == MalformedBearer.__name__)

	def test_token_required_no_auth_headers(self):
		with mock.patch('authApi.api.utils.tokenutils.request') as mocked_request:
			mocked_request.headers = dict()
			@token_required
			def a():
				return 'test_function'
			result = a()
			response = json.loads(result.data.decode())
			self.assertEqual(result.status_code, 401)
			self.assertTrue(response.get('status') == 'Fail')
			self.assertTrue(response.get('message') == str(InvalidToken()))
			self.assertTrue(response.get('error') == InvalidToken.__name__)

	def test_validate_token(self):
		user = UserModel(username='fmaketouser', password='123456')
		db.session.add(user)
		db.session.commit()
		_, refresh_token, _ = user.encode_auth_tokens(user.username)
		with mock.patch('authApi.api.utils.tokenutils.request') as mocked_request:
			mocked_request.headers = dict(Authorization='Bearer ' + refresh_token.decode())
			@validate_token
			def a():
				return 'test_function'
			result = a()
			self.assertTrue(result == 'test_function')

	def test_validate_token_expired_or_invalid_token(self):
		with mock.patch('authApi.api.utils.tokenutils.request') as mocked_request, \
			mock.patch('authApi.api.utils.tokenutils.UserModel.decode_refresh_token') as mocked_refresh_mtd, \
			mock.patch('authApi.api.utils.tokenutils.UserModel.decode_expired_token') as mocked_expired_mtd:
			mocked_request.headers = dict(Authorization='Bearer TestToken')
				
			mocked_refresh_mtd.side_effect = ExpiredToken()
			mocked_expired_mtd.return_value = json.dumps(dict(token_id='TestId'))
			@validate_token
			def a():
				return 'test_function'
			result = a()
			response = json.loads(result.data.decode())
			self.assertEqual(result.status_code, 403)
			self.assertTrue(response.get('status') == 'Fail')
			self.assertTrue(response.get('message') == str(UnauthorizedAccess()))
			self.assertTrue(response.get('error') == UnauthorizedAccess.__name__)
			
			mocked_refresh_mtd.side_effect = InvalidToken()
			@validate_token
			def a():
				return 'test_function'
			result = a()
			response = json.loads(result.data.decode())
			self.assertEqual(result.status_code, 403)
			self.assertTrue(response.get('status') == 'Fail')
			self.assertTrue(response.get('message') == str(UnauthorizedAccess()))
			self.assertTrue(response.get('error') == UnauthorizedAccess.__name__)

	def test_validate_token_blacklisted_token_or_exception(self):
		with mock.patch('authApi.api.utils.tokenutils.request') as mocked_request, \
			mock.patch('authApi.api.utils.tokenutils.UserModel.decode_refresh_token') as mocked_refresh_mtd:
			mocked_request.headers = dict(Authorization='Bearer TestToken')
			mocked_refresh_mtd.side_effect = BlacklistedToken()
			@validate_token
			def a():
				return 'test_function'
			result = a()
			response = json.loads(result.data.decode())
			self.assertEqual(result.status_code, 403)
			self.assertTrue(response.get('status') == 'Fail')
			self.assertTrue(response.get('message') == str(BlacklistedToken()))
			self.assertTrue(response.get('error') == BlacklistedToken.__name__)
	
			mocked_refresh_mtd.side_effect = Exception('TestErr')
			@validate_token
			def a():
				return 'test_function'
			result = a()
			response = json.loads(result.data.decode())
			self.assertEqual(result.status_code, 500)
			self.assertTrue(response.get('status') == 'Fail')
			self.assertTrue(response.get('message') == 'TestErr')
			self.assertTrue(response.get('error') == OtherError.__name__)

	def test_validate_request_args(self):
		with mock.patch('authApi.api.utils.tokenutils.request') as mocked_request:
			def get_json_object():
				return json.dumps(dict(nKey='nKey', tVal='tVal'))
			mocked_request.get_json = get_json_object
			@validate_request_args('nKey', 'tVal')
			def a():
				return 'test_function'
			result = a()
			self.assertTrue(result == 'test_function')

	def test_validate_request_args_missing_args(self):
		with mock.patch('authApi.api.utils.tokenutils.request') as mocked_request:
			def get_json_object():
				return json.dumps(dict(nKey='nKey',tVal='tVal'))
			mocked_request.get_json = get_json_object
			@validate_request_args('nKey1')
			def a():
				return 'test_function'
			result = a()
			response = json.loads(result.data.decode())
			self.assertEqual(result.status_code, 400)
			self.assertTrue(response.get('status') == 'Fail')
			self.assertTrue(response.get('error') == OtherError.__name__)

	def test_validate_request_args_invalid_args(self):
		with mock.patch('authApi.api.utils.tokenutils.request') as mocked_request:
			def get_json_object():
				return json.dumps(dict(nKey=None, tVal='tVal'))
			mocked_request.get_json = get_json_object
			@validate_request_args('nKey', 'tVal')
			def a():
				return 'test_function'
			result = a()
			response = json.loads(result.data.decode())
			self.assertEqual(result.status_code, 400)
			self.assertTrue(response.get('status') == 'Fail')
			self.assertTrue(response.get('error') == OtherError.__name__)

if __name__ == '__main__':
	unittest.main()

      


