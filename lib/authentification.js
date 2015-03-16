/* jslint node: true */
"use strict";

var crypto = require('crypto');
var fs = require('fs');
var https = require('https');
var Path = require('path');
var querystring = require('querystring');
var URL = require('url');

var DEFAULT_SCOPE = "credentials.r,account.r";
var AUTH_URL = "https://api.hubic.com/oauth";
var CRED_URL = "https://api.hubic.com/1.0/account/credentials";

var varsMapping = {
	client_id: 'clientId',
	client_secret: 'clientSecret',
	refresh_token: 'refreshToken'
};

function HubicAuthentification(configuration) {
	configuration = configuration || {};

	this.scope = configuration.scope || DEFAULT_SCOPE;

	this.clientId = configuration.clientId || configuration.client_id;
	this.clientSecret = configuration.clientSecret || configuration.client_secret;
	this.redirectURI = configuration.redirectURI || configuration.redirect_uri;
	this.refreshToken = configuration.refreshToken || configuration.refresh_token;
	this.configurationPath = configuration.configurationPath;

	if (!this.configurationPath) {
		var home = process.env.HOME || process.env.HOMEPATH || process.env.USERPROFILE;
		if (home) {
			this.configurationPath = home + Path.sep + ".hubicfuse";
		}

//		console.log("Config=", this.configurationPath, process.env);
	}

	this.log = (configuration.log === true && console.log.bind(console)) || configuration.log || function() {
	};
}

module.exports = HubicAuthentification;

HubicAuthentification.prototype.load = function(filename, callback) {
	if (typeof (filename) === "function") {
		callback = filename;
		filename = null;
	}

	filename = filename || this.configurationPath;

	if (!filename) {
		callback = callback || console.error.bind(console);

		return callback("Filename must be specified");
	}

	var self = this;
	fs.readFile(filename, function(error, data) {
		if (error) {
			callback = callback || console.error.bind(console);

			return callback(error);
		}
		var d = data.toString();

		d.split('\n').forEach(function(token) {
			token = token.trim();
			if (!token || token.charAt(0) === '#') {
				return;
			}

			var ret = /(.+)=(.*)/g.exec(token);
			if (!ret) {
				return;
			}

			var name = ret[1];
			var mappedName = varsMapping[name];
			if (!mappedName) {
				return;
			}

			var value = ret[2];
			self[mappedName] = value;

		});

		if (callback) {
			return callback(null, true);
		}
	});
};

HubicAuthentification.prototype.save = function(filename, callback) {
	if (typeof (filename) === "function") {
		callback = filename;
		filename = null;
	}

	filename = filename || this.configurationPath;

	if (!filename) {
		callback = callback || console.error.bind(console);

		return callback("Filename must be specified");
	}

	var config = "";

	for ( var name in varsMapping) {
		var mappedName = varsMapping[name];

		if (this[mappedName]) {
			config += name + "=" + this[mappedName] + "\n";
		}
	}

	fs.writeFile(filename, config, function(error) {
		if (error) {
			callback = callback || console.error.bind(console);
			return callback(error);
		}

		if (callback) {
			return callback(null, true);
		}
	});
};

HubicAuthentification.prototype.getTokens = function(userLogin, userPassword, callback) {
	var self = this;
	this.requestOAuth(function(error, oauth) {
		if (error) {
			return callback(error);
		}

		self.log("Oauth=", oauth);

		self.requestCode(oauth, userLogin, userPassword, function(error, code) {
			if (error) {
				return callback(error);
			}

			self.requestTokens(code, function(error, tokens) {
				return callback(error, tokens);
			});
		});
	});
};

HubicAuthentification.prototype.requestOAuth = function(callback) {

	var self = this;

	crypto.randomBytes(48, function(ex, buf) {
		if (ex) {
			return callback(ex);
		}

		var randomString = buf.toString('base64');

		var url = AUTH_URL + "/auth/?" + querystring.stringify({
			client_id: self.clientId,
			redirect_uri: self.redirectURI,
			scope: self.scope,
			response_type: "code",
			state: randomString
		});

		self.log("Request(requestOAuth) =>", url);

		var request = https.get(url, function onResponse(response) {
			response.setEncoding('utf8');

			var body = '';
			response.on('data', function(chunk) {
				body += chunk;
			});

			response.on('end', function() {

				self.log("Response(requestOAuth) status =" + response.statusCode);

				if (response.statusCode === 302) {
					return callback({
						message: "Invalid clientId or redirectURI (requestOAuth)",
						response: response
					});
				}

				if (response.statusCode !== 200) {
					return callback({
						message: "Unknown error (requestOAuth)",
						response: response
					});
				}

				var regexp = /.*name="oauth" value="([^"]+)">.*/g;

				var ret = regexp.exec(body);
				if (!ret || !ret[1]) {
					return callback({
						message: "Invalid page format (requestOAuth)",
						response: response,
						body: body
					});
				}

				var oauth = ret[1];

				return callback(null, oauth);
			});
		});
	});
};

HubicAuthentification.prototype.requestCode = function(oauth, userLogin, userPassword, callback) {

	var url = AUTH_URL + "/auth/";

	var data = {
		oauth: oauth,
		action: "accepted",
		login: userLogin,
		user_pwd: userPassword
	};

	this.scope.split(',').forEach(function(token) {
		var ts = token.split('.');

		var name = ts[0];
		var value = ts[1];

		if (!data[name]) {
			data[name] = [];
		}

		data[name].push(value);
	});

	var options = URL.parse(url);
	options.method = "POST";
	options.headers = {
		'Content-Type': 'application/x-www-form-urlencoded'
	};

	this.log("Request(requestCode) =>", options);

	var self = this;

	var request = https.request(options, function(response) {
		self.log("Response(requestCode)", response.statusCode);
		if (response.statusCode === 200) {
			return callback({
				message: "Wrong username or password (requestCode)",
				response: response
			});
		}
		if (response.statusCode !== 302) {
			return callback({
				message: "Unknown error (requestCode)",
				response: response
			});
		}

		response.setEncoding('utf8');

		var body = '';
		response.on('data', function(chunk) {
			body += chunk;
		});

		response.on('end', function() {
			// console.log("Data=", body);

			var location = response.headers.location;
			if (!location) {
				return callback({
					message: "Invalid location redirection (requestCode)",
					response: response
				});
			}

			var locationURL = URL.parse(location, true);

			var code = locationURL.query.code;
			if (!code) {
				return callback({
					message: "Invalid query string " + location + " (requestCode)",
					response: response,
					location: locationURL
				});
			}

			return callback(null, code);
		});
	});

	var postData = querystring.stringify(data);

	self.log("PostData(requestCode)=" + postData);
	request.write(postData);
	request.end();
};

HubicAuthentification.prototype.requestTokens = function(code, callback) {

	var url = AUTH_URL + "/token/";

	var data = {
		client_id: this.clientId,
		client_secret: this.clientSecret,
		code: code,
		grant_type: "authorization_code",
		redirect_uri: this.redirectURI
	};

	var options = URL.parse(url);
	options.method = "POST";
	options.headers = {
		'Content-Type': 'application/x-www-form-urlencoded'
	};

	this.log("Request(requestTokens) =>", options);

	var self = this;
	var request = https.request(options, function(response) {
		self.log("Response(requestTokens)", response.statusCode);

		if (response.statusCode === 401) {
			return callback({
				message: "Invalid client_secret (requestTokens)",
				response: response
			});
		}
		if (response.statusCode !== 200) {
			return callback({
				message: "Unknown error (requestTokens)",
				response: response
			});
		}

		response.setEncoding('utf8');

		var body = '';
		response.on('data', function(chunk) {
			body += chunk;
		});

		response.on('end', function() {

			var json = JSON.parse(body);

			self.log("Tokens=", json);

			if (json.refresh_token) {
				self.refreshToken = json.refresh_token;
			}

			if (json.access_token) {
				self.accessToken = json.access_token;
			}

			return callback(null, json);
		});

		request.on('error', function(e) {

			return callback({
				message: "Request error (requestTokens)",
				error: e,
				request: request
			});
		});
	});

	var postData = querystring.stringify(data);

	self.log("PostData(requestTokens)=" + postData);
	request.write(postData);
	request.end();
};

HubicAuthentification.prototype.getRefreshToken = function(refreshToken, callback) {

	if (typeof (refreshToken) === "function") {
		callback = refreshToken;
		refreshToken = null;
	}

	var url = AUTH_URL + "/token/";

	var data = {
		refresh_token: refreshToken || this.refreshToken,
		grant_type: "refresh_token",
	};

	var auth = "Basic " + new Buffer(this.clientId + ":" + this.clientSecret).toString("base64");

	var options = URL.parse(url);
	options.method = "POST";
	options.headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': auth
	};

	this.log("Request(getRefreshToken) =>", options);

	var self = this;
	var request = https.request(options, function(response) {
		self.log("Response(getRefreshToken) ", response.statusCode);

		if (response.statusCode !== 200) {
			return callback({
				message: "Unknown error (refresh_token)",
				response: response
			});
		}

		response.setEncoding('utf8');

		var body = '';
		response.on('data', function(chunk) {
			body += chunk;
		});

		response.on('end', function() {

			var json = JSON.parse(body);

			self.log("Refreshed tokens =", json);

			if (json.access_token) {
				self.accessToken = json.access_token;
			}

			return callback(null, json);
		});

		request.on('error', function(e) {

			return callback({
				message: "Request error (refresh_tokens)",
				error: e,
				request: request
			});
		});
	});

	var postData = querystring.stringify(data);

	self.log("PostData(refresh_tokens)=" + postData);
	request.write(postData);
	request.end();

};

HubicAuthentification.prototype.clearAccessToken = function() {
	this.accessToken = null;
	this.storageToken = null;
	this.storageEndpoint = null;
	this.storageExpires = null;
};

HubicAuthentification.prototype.getAccessToken = function(userPasswordRequestedCallback, callback) {
	if (this.accessToken && clearPreviousTokens !== true) {
		return callback(null, this.accessToken);
	}

	var self = this;
	if (this.refreshToken) {
		return this.getRefreshToken(this.refreshToken, function(error, tokens) {
			if (error) {
				return callback(error);
			}

			return callback(null, self.accessToken);
		});
	}

	if (!userPasswordRequestedCallback) {
		return callback("Need a username and a password");
	}

	userPasswordRequestedCallback(function(error, user, password) {
		if (error) {
			return callback(error);
		}

		self.getTokens(user, password, function(error, tokens) {
			if (error) {
				return callback(error);
			}

			return callback(null, self.accessToken);
		});
	});
};

HubicAuthentification.prototype.requestStorageURL = function(accessToken, callback) {

	if (typeof (accessToken) === "function") {
		callback = accessToken;
		accessToken = null;
	}

	if (!accessToken) {
		accessToken = this.accessToken;

		if (!accessToken) {
			return callback("Unknown accessToken !");
		}
	}

	var options = URL.parse(CRED_URL);
	options.method = "GET";
	options.headers = {
		'Authorization': "Bearer " + accessToken
	};

	this.log("Request(requestStorageURL) =>", options);

	var self = this;
	var request = https.request(options, function(response) {
		self.log("Response(requestStorageURL) ", response.statusCode);

		if (response.statusCode !== 200) {
			return callback({
				message: "Unknown error (refresh_token)",
				response: response
			});
		}

		response.setEncoding('utf8');

		var body = '';
		response.on('data', function(chunk) {
			body += chunk;
		});

		response.on('end', function() {

			var json = JSON.parse(body);

			self.log("requestStorageURL =", json);

			if (json.token) {
				this.storageToken = json.token;
			}

			if (json.endpoint) {
				this.storageEndpoint = json.endpoint;
			}

			if (json.expires) {
				this.storageExpires = new Date(json.expires);
			}

			return callback(null, json);
		});

		request.on('error', function(e) {

			return callback({
				message: "Request error (requestStorageURL)",
				error: e,
				request: request
			});
		});
	});

	request.end();
}

HubicAuthentification.prototype.getStorageInfos = function(userPasswordRequestedCallback, callback) {
	if (arguments.length === 1) {
		callback = userPasswordRequestedCallback;
		userPasswordRequestedCallback = null;
	}

	if (this.storageToken) {
		return {
			token: storageToken,
			endpoint: storageEndpoint
		}
	}

	var self = this;
	this.getAccessToken(userPasswordRequestedCallback, function(error, accessToken) {
		if (error) {
			return callback(error);
		}

		return self.requestStorageURL(accessToken, callback);
	});
};
