import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
dotenv_path = os.path.join(basedir, '.env')
load_dotenv(dotenv_path)

class BaseConfig(object):
	SECRET_KEY = os.getenv('SECRET_KEY')
	DEBUG = False

class DevelopmentConfig(BaseConfig):
	DEBUG = True
	SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, os.getenv('DEV_DATABASE_FILE_NAME'))
	SQLALCHEMY_TRACK_MODIFICATIONS = False

class TestingConfig(BaseConfig):
	DEBUG = True
	TESTING = True
	SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, os.getenv('TEST_DATABASE_FILE_NAME'))
	PRESERVE_CONTEXT_ON_EXCEPTION = False
	SQLALCHEMY_TRACK_MODIFICATIONS = False
 
config_by_name = dict(
	dev=DevelopmentConfig,
	test=TestingConfig
)

key = BaseConfig.SECRET_KEY
