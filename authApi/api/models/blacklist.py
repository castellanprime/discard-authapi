from authApi.api import db
import uuid
import datetime

class BlackListTokenModel(db.Model):
	"""Token model for storing token"""
	__tablename__ = 'blacklistedTokens'
	
	id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	token_id = db.Column(db.String(60), default=" ", unique=True, nullable=False)
	token = db.Column(db.String(100), nullable=True)
	is_there_a_user = db.Column(db.Boolean, default=True, nullable=False)	# If there is no user associated with the token
	blacklisted_on = db.Column(db.DateTime)
	
	def __init__(self, token_id=uuid.uuid4().hex, token=None):
		self.token_id = token_id
		self.token = token
		if token:
			self.is_there_a_user = False
		self.blacklisted_on = datetime.datetime.now()

	@staticmethod
	def check_blacklist(refresh_token_id, token):
		res = BlackListTokenModel.query.filter_by(token_id=str(refresh_token_id)).first()
		if res:
			return True

		res = BlackListTokenModel.query.filter_by(token=str(token)).first()
		if res:
			return True
		
		return False


	def __repr__(self):
		return '<id: token_id: {}'.format(self.token_id)
