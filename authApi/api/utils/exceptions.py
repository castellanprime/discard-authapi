# Exception classes

class InvalidToken(Exception):
	def __init__(self, message='Please provide a valid authorization Token'):
		super().__init__(message)

class ExpiredToken(Exception):
	def __init__(self, message='Signature expired'):
		super().__init__(message)

class BlacklistedToken(Exception):
	def __init__(self, message='Token is already blacklisted'):
		super().__init__(message)

class UnauthorizedAccess(Exception):
	def __init__(self, message='You are not authorized to access this resource'):
		super().__init__(message)

class MalformedBearer(Exception):
	def __init__(self, message='Bearer message malformed. Need a space after the "Bearer" word'):
		super().__init__(message)

class UserDoesNotExist(Exception):
	def __init__(self, message='User does not exist'):
		super().__init__(message)

class UserAlreadyExist(Exception):
	def __init__(self, message='User already exists'):
		super().__init__(message)

class OtherError(Exception):
	def __init__(self, message):
		super().__init__(message)
