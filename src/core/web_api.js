import auth0 from 'auth0-js';
import Auth0LegacyAPIClient from './web_api/legacy_api'
import Auth0APIClient from './web_api/p2_api'

class Auth0WebAPI {
  constructor() {
    this.clients = {};
  }

  setupClient(lockID, clientID, domain, opts) {
    if (opts.legacyMode) {
      this.clients[lockID] = new Auth0LegacyAPIClient(clientID, domain, opts);
    } else {
      this.clients[lockID] = new Auth0APIClient(clientID, domain, opts);
    }
  }

  logIn(lockID, options, authParams, cb) {
    this.clients[lockID].logIn(options, authParams, cb);
  }

  signOut(lockID, query) {
    this.clients[lockID].logout(query);
  }

  signUp(lockID, options, cb) {
    this.clients[lockID].signUp(options, cb);
  }

  resetPassword(lockID, options, cb) {
    this.clients[lockID].changePassword(options, (err, data) => cb(err, data && data.countryCode));
  }

  startPasswordless(lockID, options, cb) {
    this.clients[lockID].startPasswordless(options, cb);
  }

  parseHash(lockID, hash = '') {
    return this.clients[lockID].parseHash(decodeURIComponent(hash));
  }

  getUserInfo(lockID, token, callback) {
    return this.clients[lockID].getUserInfo(token, callback);
  }

  getSSOData(lockID, ...args) {
    return this.clients[lockID].getSSOData(...args);
  }

  getUserCountry(lockID, cb) {
    return this.clients[lockID].getUserCountry(cb);
  }
}

export default new Auth0WebAPI();
<<<<<<< a1070ebfc887a0c369f1c8c8dacdb221a0d12f5c

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
=======
>>>>>>> move legacy and p2 to different clases
