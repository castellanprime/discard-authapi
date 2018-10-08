from authApi.api import db
import datetime

class BlackListTokenModel(db.Model):
	"""Token model for storing token"""
	__tablename__ = 'blacklistedTokens'
	
	id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	token_id = db.Column(db.String(500), unique=True, nullable=False)
	blacklisted_on = db.Column(db.DateTime, nullable=False)
	
	def __init__(self, token_id):
		self.token_id = token_id
		self.blacklisted_on = datetime.datetime.now()

	@staticmethod
	def check_blacklist(refresh_token_id):
		res = BlackListTokenModel.query.filter_by(token_id=str(refresh_token_id)).first()
		if res:
			return True
		else:
			return False

	def __repr__(self):
		return '<id: token_id: {}'.format(self.token_id)
