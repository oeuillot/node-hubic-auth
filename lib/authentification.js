/*jslint node: true, plusplus:true, node: true, esversion: 6 */
"use strict";

var debug = require('debug')('hubic-auth');
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

class HubicAuthentification {
  constructor(configuration) {
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

// console.log("Config=", this.configurationPath, process.env);
    }
  }

  load(filename, callback) {
    if (typeof (filename) === "function") {
      callback = filename;
      filename = null;
    }

    filename = filename || this.configurationPath;

    if (!filename) {
      callback = callback || console.error.bind(console);

      return callback("Filename must be specified");
    }

    fs.readFile(filename, (error, data) => {
      if (error) {
        callback = callback || console.error.bind(console);

        return callback(error);
      }
      
      var d = data.toString();

      d.split('\n').forEach((token) => {
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
        this[mappedName] = value;
      });

      if (callback) {
        return callback(null, true);
      }
    });
  }

  save(filename, callback) {
    if (typeof (filename) === "function") {
      callback = filename;
      filename = null;
    }

    filename = filename || this.configurationPath;

    debug("Save to",filename);
    
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

    fs.writeFile(filename, config, (error) => {
      debug("Save done error=", error);
      if (error) {
        callback = callback || console.error.bind(console);
        return callback(error);
      }

      if (callback) {
        return callback(null, true);
      }
    });
  }

  getTokens(userLogin, userPassword, callback) {
    this.requestOAuth((error, oauth) => {
      debug("getTokens: Request Oauth=", oauth, "error=",error);

      if (error) {
        return callback(error);
      }

      this.requestCode(oauth, userLogin, userPassword, (error, code) => {
        if (error) {
          return callback(error);
        }

        this.requestTokens(code, (error, tokens) => {
          callback(error, tokens);
        });
      });
    });
  }

  requestOAuth(callback) {
    crypto.randomBytes(48, (ex, buf) => {
      if (ex) {
        return callback(ex);
      }

      var randomString = buf.toString('base64');

      var url = AUTH_URL + "/auth/?" + querystring.stringify({
        client_id: this.clientId,
        redirect_uri: this.redirectURI,
        scope: this.scope,
        response_type: "code",
        state: randomString
      });

      debug("Request(requestOAuth) =>", url);

      https.get(url, (response) => {
        response.setEncoding('utf8');

        var body = '';
        response.on('data', (chunk) => {
          body += chunk;
        });

        response.on('end', () => {

          debug("Response(requestOAuth) status =", response.statusCode);

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
  }

  requestCode(oauth, userLogin, userPassword, callback) {

    var url = AUTH_URL + "/auth/";

    var data = {
        oauth: oauth,
        action: "accepted",
        login: userLogin,
        user_pwd: userPassword
    };

    this.scope.split(',').forEach((token) => {
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

    debug("Request(requestCode) =>", options);

    var request = https.request(options, (response) => {
      debug("Response(requestCode)", response.statusCode);
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
      response.on('data', (chunk) => {
        body += chunk;
      });

      response.on('end', () => {
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

    debug("PostData(requestCode)=" + postData);
    request.write(postData);
    request.end();
  }

  requestTokens(code, callback) {

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

    debug("Request(requestTokens) =>", options);

    var request = https.request(options, (response) => {
      debug("Response(requestTokens)", response.statusCode);

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
      response.on('data', (chunk) => {
        body += chunk;
      });

      response.on('end', () => {

        var json = JSON.parse(body);

        debug("Tokens=", json);

        if (json.refresh_token) {
          this.refreshToken = json.refresh_token;
        }

        if (json.access_token) {
          this.accessToken = json.access_token;
        }

        callback(null, json);
      });

      request.on('error', (e) => {

        return callback({
          message: "Request error (requestTokens)",
          error: e,
          request: request
        });
      });
    });

    var postData = querystring.stringify(data);

    debug("PostData(requestTokens)=", postData);
    request.write(postData);
    request.end();
  }

  getRefreshToken(refreshToken, callback) {

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

    debug("Request(getRefreshToken) =>", options);

    var request = https.request(options, (response) => {
      debug("Response(getRefreshToken) ", response.statusCode);

      if (response.statusCode !== 200) {
        return callback({
          message: "Unknown error (refresh_token)",
          response: response
        });
      }

      response.setEncoding('utf8');

      var body = '';
      response.on('data', (chunk) => {
        body += chunk;
      });

      response.on('end', () => {

        var json = JSON.parse(body);

        debug("Refreshed tokens =", json);

        if (json.access_token) {
          this.accessToken = json.access_token;
        }

        return callback(null, json);
      });

      request.on('error', (e) => {

        return callback({
          message: "Request error (refresh_tokens)",
          error: e,
          request: request
        });
      });
    });

    var postData = querystring.stringify(data);

    debug("PostData(refresh_tokens)=" + postData);
    request.write(postData);
    request.end();
  }

  clearAccessToken() {
    this.accessToken = null;
    this.storageToken = null;
    this.storageEndpoint = null;
    this.storageExpires = null;
  }

  getAccessToken(userPasswordRequestedCallback, callback) {
    if (this.accessToken && clearPreviousTokens !== true) {
      return callback(null, this.accessToken);
    }

    if (this.refreshToken) {
      this.getRefreshToken(this.refreshToken, (error, tokens) => {
        if (error) {
          return callback(error);
        }
        
        // Might save ?
        
        if (this._options.saveTokens) {
          this.save((error) => {
            if (error) {
              console.error(error);
            }
            callback(null, this.accessToken);
          })
          return;
        }

        callback(null, this.accessToken);
      });
      return;
    }

    if (!userPasswordRequestedCallback) {
      return callback("Need a username and a password");
    }

    userPasswordRequestedCallback((error, user, password) => {
      if (error) {
        return callback(error);
      }

      this.getTokens(user, password, (error, tokens) => {
        if (error) {
          return callback(error);
        }

        callback(null, this.accessToken);
      });
    });
  };

  requestStorageURL(accessToken, callback) {

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

    debug("Request(requestStorageURL) =>", options);

    var request = https.request(options, (response) => {
      debug("Response(requestStorageURL) ", response.statusCode);

      if (response.statusCode !== 200) {
        return callback({
          message: "Unknown error (refresh_token)",
          response: response
        });
      }

      response.setEncoding('utf8');

      var body = '';
      response.on('data', (chunk) => {
        body += chunk;
      });

      response.on('end', () => {

        var json = JSON.parse(body);

        debug("requestStorageURL =", json);

        if (json.token) {
          this.storageToken = json.token;
        }

        if (json.endpoint) {
          this.storageEndpoint = json.endpoint;
        }

        if (json.expires) {
          this.storageExpires = new Date(json.expires);
        }

        callback(null, json);
      });

      request.on('error', (e) => {
        callback({
          message: "Request error (requestStorageURL)",
          error: e,
          request: request
        });
      });
    });

    request.end();
  }

  getStorageInfos(userPasswordRequestedCallback, callback) {
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

    this.getAccessToken(userPasswordRequestedCallback, (error, accessToken) => {
      if (error) {
        return callback(error);
      }

      this.requestStorageURL(accessToken, callback);
    });
  }
}

module.exports = HubicAuthentification;
