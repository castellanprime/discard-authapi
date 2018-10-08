import jwt, datetime, uuid, json

from authApi.api import db, flask_bcrypt
from ..config import key
from .blacklist import BlackListTokenModel

class UserModel(db.Model):
	"""User model for users in the system"""
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	registered_on = db.Column(db.DateTime, nullable=False)
	admin = db.Column(db.Boolean, nullable=False, default=False)
	password_hash = db.Column(db.String(100), nullable=False)
	username = db.Column(db.String(15), unique=True)
	token_id = db.Column(db.String(60), unique=True)
	updated_on = db.Column(db.DateTime)
	updated_by = db.Column(db.String(15))
	
	def __init__(self, password, username, admin=False):
		self.username = username
		self.password_hash = flask_bcrypt.generate_password_hash(password).decode('utf-8')
		self.registered_on = datetime.datetime.utcnow()
		self.admin = False

	def check_password(self, password):
		return flask_bcrypt.check_password_hash(self.password_hash, password)

	def encode_auth_tokens(self, username):
		"""
        	Generates the tokens, auth token and refresh token
        	:return: string
       		"""
		try:
			current_time = datetime.datetime.utcnow()
			refresh_token_id = uuid.uuid4().hex
			auth_token_payload = {
				'exp': current_time + datetime.timedelta(minutes=20),
				'iat': current_time,
				'sub': username
			}
			refresh_token_payload = {
				'exp': current_time + datetime.timedelta(days=1),
				'iat': current_time,
				'sub': username,
				'jti': refresh_token_id,
				'admin':self.admin,
			}
			auth_token = jwt.encode(auth_token_payload, key, algorithm='HS256')
			refresh_token = jwt.encode(refresh_token_payload, key, algorithm='HS256')
			return (auth_token, refresh_token, refresh_token_id)
		except Exception as e:
			return e

	@staticmethod
	def decode_refresh_token(refresh_token):
		"""
        	Validates the refresh token
        	:param refresh_token:
        	:return: integer|string
        	"""
		try:
			payload = jwt.decode(refresh_token, key)
			is_blacklisted = BlackListTokenModel.check_blacklist(payload['jti'])
			if is_blacklisted:
				return 'Token blacklisted.Please log in again'
			else:
				return json.dumps(dict(
					name=payload['sub'],
					admin=payload['admin']
				))
		except jwt.ExpiredSignatureError:
			return 'Signature expired. Please log in again'
		except jwt.InvalidTokenError:
			return 'Invalid token. Please log in again'

	def __repr__(self):
		return "<User'{}'>".format(self.username)  
