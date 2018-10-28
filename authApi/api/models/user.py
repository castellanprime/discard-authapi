import jwt, datetime, uuid, json

from authApi.api import db, flask_bcrypt
from authApi.api.utils.exceptions import (
	ExpiredToken,
	InvalidToken,
	BlacklistedToken
)
from ..config import key
from .blacklist import BlackListTokenModel
from sqlalchemy.orm import validates

class UserModel(db.Model):
	"""User model for users in the system"""
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key=True, autoincrement=True)	# database id
	public_id = db.Column(db.String(60), unique=True)			# for retrieval
	registered_on = db.Column(db.DateTime, nullable=False)
	admin = db.Column(db.Boolean, nullable=False, default=False)
	anonymous = db.Column(db.Boolean, nullable=False, default=False)
	password_hash = db.Column(db.String(100), nullable=False)
	username = db.Column(db.String(15))					# allows for name to change
	token_id = db.Column(db.String(60), default=" ", nullable=True)
	updated_on = db.Column(db.DateTime)
	updated_by = db.Column(db.String(15))
	
	def __init__(self, password, username, admin=False, anonymous=False):
		self.username = username
		self.public_id = uuid.uuid4().hex
		self.password_hash = flask_bcrypt.generate_password_hash(password).decode('utf-8')
		self.registered_on = datetime.datetime.utcnow()
		self.admin = admin
		self.anonymous = anonymous

	# @validates
	# def validate_admin(self, admin):
	# 	if isinstance(admin, bool):
	# 		raise AssertionError('Admin has to be boolean')
	# 	return admin

	# @validates
	# def validate_anonymous(self, anonymous):
	# 	if isinstance(anonymous, bool):
	# 		raise AssertionError('Anonymous has to be boolean')
	# 	return anonymous

	# @validates
	# def validate_username(self, username):
	# 	if isinstance(username, str):
	# 		raise AssertionError('Username has to be a string')

	# 	if len(username.strip()) == 0:
	# 		raise AssertionError('Username can not be empty')

	# 	return username 

	def check_password(self, password):
		return flask_bcrypt.check_password_hash(self.password_hash, password)

	def change_password(self, password, principal=''):		# principal is the person making this change
		self.password_hash = flask_bcrypt.generate_password_hash(password).decode('utf-8')
		self.updated_on = datetime.datetime.utcnow()
		if len(principal.strip()) == 0:
			self.updated_by = self.public_id
		else:
			self.updated_by = principal

	def change_username(self, username, principal=''):
		self.username = username
		if len(principal.strip()) == 0:
			self.updated_by = self.public_id
		else:
			self.updated_by = principal 

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
				'sub': self.public_id,
				'jti': refresh_token_id,
				'admin':self.admin,
				'anonymous': self.anonymous
			}
			auth_token = jwt.encode(auth_token_payload, key, algorithm='HS256')
			refresh_token = jwt.encode(refresh_token_payload, key, algorithm='HS256')
			return (auth_token, refresh_token, refresh_token_id)
		except Exception as e:
			return e

	def encode_access_token(self, username):
		""" 
		Generate new access token
		:return: string
		"""
		try:
			current_time = datetime.datetime.utcnow()
			access_token_payload = dict(
				exp=current_time + datetime.timedelta(minutes=20),
				iat=current_time,
				sub=username
			)
			return jwt.encode(access_token_payload, key, algorithm='HS256')
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
			is_blacklisted = BlackListTokenModel.check_blacklist(payload.get('jti'), token=refresh_token)
			if is_blacklisted:
				raise BlacklistedToken()
			else:
				return json.dumps(dict(
					name=payload.get('sub'),
					admin=payload.get('admin'),
					anonymous=payload.get('anonymous')
				))
		except jwt.ExpiredSignatureError:
			raise ExpiredToken()
		except jwt.InvalidTokenError:
			raise InvalidToken()

	@staticmethod
	def decode_expired_token(expired_token):
		"""
		Returns expired token contents
		:param: expired_token
		:return: object
		"""
		payload = jwt.decode(expired_token, verify=False)
		return json.dumps(dict(
			name=payload.get('sub'),
			token_id=payload.get('jti')
		))

	def __repr__(self):
		return "<User'{}', token_id={}>".format(self.username, self.token_id)  
