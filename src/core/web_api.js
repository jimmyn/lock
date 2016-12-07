import auth0 from 'auth0-js';

class Auth0WebAPI {
  constructor() {
    this.clients = {};
    this.authOpts = {};
    this.authParams = {};
  }

  setupClient(lockID, clientID, domain, opts) {

    const default_telemetry = {
      name: 'lock.js',
      version: __VERSION__,
      lib_version: auth0.version
    };

    this.clients[lockID] = new auth0.WebAuth({
      clientID: clientID,
      domain: domain,
      redirectUri: opts.redirectUrl,
      responseMode: opts.responseMode,
      responseType: opts.responseType,
      __tenant: opts.overrides && opts.overrides.__tenant,
      __token_issuer: opts.overrides && opts.overrides.__token_issuer,
      legacyMode: opts.legacyMode === false ? false : true,
      _sendTelemetry: opts._sendTelemetry === false ? false : true,
      _telemetryInfo: opts._telemetryInfo || default_telemetry
    });

    this.authOpts[lockID] = {
      popup: !opts.redirect,
      popupOptions: opts.popupOptions,
      sso: opts.sso
    };
  }

  logIn(lockID, options, authParams, cb) {
    // TODO: for passwordless only, try to clean in auth0.js
    // client._shouldRedirect = redirect || responseType === "code" || !!redirectUrl;
    const authOpts = this.authOpts[lockID];
    const f = loginCallback(!authOpts.popup, cb);
    const client = this.clients[lockID];

    if (!this.authOpts[lockID].legacyMode) {
      options.realm = options.connection;
      client.client.loginRealm({...options, ...authOpts, ...authParams}, f);
    } else if (authOpts.popup) {
      client.popup.login({...options, ...authOpts, ...authParams}, f)
    } else {
      client.redirect.login({...options, ...authOpts, ...authParams}, f);
    }
  }

  signOut(lockID, query) {
    this.clients[lockID].logout(query);
  }

  signUp(lockID, options, cb) {
    const client = this.clients[lockID];
    const { popup, sso } = this.authOpts[lockID];
    const { autoLogin } = options;

    delete options.autoLogin;

    const popupHandler = (autoLogin && popup) ? client.popup.preload() : null;

    client.signup(options, (err, result) => cb(err, result, popupHandler) );
  }

  resetPassword(lockID, options, cb) {
    this.clients[lockID].changePassword(options, cb);
  }

  startPasswordless(lockID, options, cb) {
    const client = this.clients[lockID];
    client.startPasswordless(options, err => cb(normalizeError(err)));
  }

  parseHash(lockID, hash = '') {
    return this.clients[lockID].parseHash(decodeURIComponent(hash));
  }

  getUserInfo(lockID, token, callback) {
    return this.clients[lockID].client.userInfo(token, callback);
  }

  getSSOData(lockID, ...args) {
    return this.clients[lockID].client.getSSOData(...args);
  }

  getUserCountry(lockID, cb) {
    return this.clients[lockID].getUserCountry(cb);
  }
}

export default new Auth0WebAPI();

function normalizeError(error) {
  if (!error) {
    return error;
  }

  // TODO: clean this mess, the first checks are for social/popup,
  // then we have some stuff for passwordless and the latter is for
  // db.

  // TODO: the following checks were copied from https://github.com/auth0/lock/blob/0a5abf1957c9bb746b0710b274d0feed9b399958/index.js#L1263-L1288
  // Some of the checks are missing because I couldn't reproduce them and I'm
  // affraid they'll break existent functionality if add them.
  // We need a better errror handling story in auth0.js.

  if (error.status === "User closed the popup window") {
    // {
    //   status: "User closed the popup window",
    //   name: undefined,
    //   code: undefined,
    //   details: {
    //     description: "server error",
    //     code: undefined
    //   }
    // }
    return {
      code: "lock.popup_closed",
      error: "lock.popup_closed",
      description: "Popup window closed."
    };
  }

  if (error.code === "unauthorized") {

    // Custom rule error
    //
    // {
    //   "code": "unauthorized",
    //   "details": {
    //     "code": "unauthorized",
    //     "error_description": "user is blocked",
    //     "error": "unauthorized"
    //   },
    //   "name": "unauthorized",
    //   "status": 401
    // }

    // Default "user is blocked" rule error
    //
    // {
    //   "code": "unauthorized",
    //   "details": {
    //     "code": "unauthorized",
    //     "error_description": "user is blocked",
    //     "error": "unauthorized"
    //   },
    //   "name": "unauthorized",
    //   "status": 401
    // }

    // Social cancel permissions.
    //
    // {
    //   code: "unauthorized",
    //   details: {
    //     code: "unauthorized"
    //     error: "unauthorized"
    //     error_description: "access_denied"
    //   },
    //   name: "unauthorized"
    //   status: 401
    // }

    // Social cancel permissions or unknown error
    if (!error.details
        || !error.details.error_description
        || error.details.error_description === "access_denied") {

      return {
        code: "lock.unauthorized",
        error: "lock.unauthorized",
        description: (error.details && error.details.error_description) || "Permissions were not granted."
      }
    }

    // Special case for custom rule error
    if (error.details.error_description === "user is blocked") {
      return {
        code: "blocked_user",
        error: "blocked_user",
        description: error.details.error_description
      };
    }

    // Custom Rule error
    return {
      code: "rule_error",
      error: "rule_error",
      description: error.details.error_description
    };

  }

  const result = {
    error: error.details ? error.details.error : (error.code || error.statusCode || error.error),
    description: error.details ? error.details.error_description : (error.error_description || error.description || error.error)
  }

  // result is used for passwordless and error for database.
  return result.error === undefined && result.description === undefined
    ? error
    : result;
}

function loginCallback(redirect, cb) {
  return redirect
    ? error => cb(normalizeError(error))
    : (error, result) => cb(normalizeError(error), result);
}
