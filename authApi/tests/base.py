from flask_testing import TestCase

from authApi.api import db, create_app
from authApi.api.config import config_by_name

class BaseTestCase(TestCase):
	"""Base Tests"""
	def create_app(self):
		return create_app('test')

	def setUp(self):
		db.create_all()
		db.session.commit()

	def tearDown(self):
		db.session.remove()
		db.drop_all()

