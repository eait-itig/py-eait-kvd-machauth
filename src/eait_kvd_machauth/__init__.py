#
# Copyright 2021 The University of Queensland
# Author: Alex Wilson <alex@uq.edu.au>
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 

import requests, json
import base64, time, struct
import hmac, hashlib
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

from typing import Optional

class MachAuthError(Exception):
	"""
	An HTTP error which occurred during machine auth to api.uqcloud.net.
	"""
	def __init__(self, code : int, text : str):
		self.text = text
		"""
		The textual error message received.
		"""
		self.code = code
		"""
		The HTTP status code received.
		"""
	def __str__(self):
		return repr(self.code) + ": " + repr(self.text)

class MachAuthToken(object):
	"""
	A machine authentication token for use against uqcloud.net APIs.
	"""
	def __init__(self, uid : str, key : str, endpoint : str):
		"""
		`uid` and `key` must be obtained from api.uqcloud.net. `key` is
		base64-encoded.

		The `endpoint` argument must be set to the hostname of the
		final target API.
		"""
		self.__uid = uid
		self.__key = base64.b64decode(key)
		self.__endpoint = endpoint
		self.__cookie = None

	"""
	The UID this token authenticate as. Note that this may not match
	the username presented to the backing API service.
	"""
	@property
	def uid(self) -> str:
		return self.__uid

	"""
	The API URL this token is associated with.
	"""
	@property
	def endpoint(self):
		return self.__endpoint

	@property
	def cookie(self) -> str:
		"""
		Generates a session cookie for the machine auth user. This
		value should be provided in the `EAIT_WEB` cookie to the
		target API.
		"""
		if self.__cookie:
			return self.__cookie

		t = int(time.time())
		sigblob = struct.pack(">Q", t) + self.endpoint.encode('ascii')
		hm = hmac.new(self.__key, sigblob, hashlib.sha256)
		sig = hm.digest()
		blob = json.dumps({
			'time': t,
			'target': self.endpoint,
			'user': self.uid,
			'signature': base64.b64encode(sig).decode('ascii'),
			'algorithm': 2 # hmac_sha256
		})
		hdrs = {'content-type': 'application/json'}
		r = requests.post('https://api.uqcloud.net/machauth',
		     data = blob, headers = hdrs)
		if r.status_code == 200:
			reply = r.json()
			self.__cookie = reply["cookie"]
			return self.__cookie
		else:
			raise MachAuthError(r.status_code, r.text)

class APIClient(object):
	"""
	A wrapper for a Requests session which injects a MachAuthToken cookie
	with each request.
	"""
	def __init__(self, auth : MachAuthToken, endpoint : Optional[str] = None):
		self.__auth = auth
		if endpoint is None:
			self.__endpoint = auth.endpoint
		else:
			self.__endpoint = endpoint
		self.__sess = requests.Session()
		retries = Retry(total=5, backoff_factor=1,
		    status_forcelist=[ 502, 503, 504 ])
		self.__sess.mount('https://', HTTPAdapter(max_retries = retries))

	def get(self, path : str, **kwargs):
		cookies = {"EAIT_WEB": self.__auth.cookie}
		return self.__sess.get('https://' + self.__endpoint + path,
		    cookies = cookies, **kwargs)

	def post(self, path : str, **kwargs):
		cookies = {"EAIT_WEB": self.__auth.cookie}
		return self.__sess.post('https://' + self.__endpoint + path,
		    cookies = cookies, **kwargs)

	def put(self, path : str, **kwargs):
		cookies = {"EAIT_WEB": self.__auth.cookie}
		return self.__sess.put('https://' + self.__endpoint + path,
		    cookies = cookies, **kwargs)

	def patch(self, path : str, **kwargs):
		cookies = {"EAIT_WEB": self.__auth.cookie}
		return self.__sess.patch('https://' + self.__endpoint + path,
		    cookies = cookies, **kwargs)

	def delete(self, path : str, **kwargs):
		cookies = {"EAIT_WEB": self.__auth.cookie}
		return self.__sess.delete('https://' + self.__endpoint + path,
		    cookies = cookies, **kwargs)

	def request(self, method : str, path : str, **kwargs):
		cookies = {"EAIT_WEB": self.__auth.cookie}
		return self.__sess.request(method,
		    'https://' + self.__endpoint + path,
		    cookies = cookies, **kwargs)

