import auth0 from 'auth0-js';
import {normalizeError, loginCallback} from './helper';

class Auth0LegacyAPIClient {
  constructor(clientID, domain, opts) {
    this.client = null;
    this.authOpt = null;

    const default_telemetry = {
      name: 'lock.js',
      version: __VERSION__,
      lib_version: auth0.version
    };

    this.client = new auth0.WebAuth({
      clientID: clientID,
      domain: domain,
      redirectUri: opts.redirectUrl,
      responseMode: opts.responseMode,
      responseType: opts.responseType,
      _sendTelemetry: opts._sendTelemetry === false ? false : true,
      _telemetryInfo: opts._telemetryInfo || default_telemetry
    });

    this.authOpt = {
      popup: !opts.redirect,
      popupOptions: opts.popupOptions,
      sso: opts.sso
    };
  }

  logIn(options, authParams, cb) {
    // TODO: for passwordless only, try to clean in auth0.js
    // client._shouldRedirect = redirect || responseType === "code" || !!redirectUrl;
    const f = loginCallback(!this.authOpt.popup, cb);
    const auth0Client = this.client;

    if (!options.username && !options.email) {
      if (this.authOpt.popup) {
        auth0Client.popup.authorize({...options, ...this.authOpt, ...authParams}, f)
      } else {
        auth0Client.login({...options, ...this.authOpt, ...authParams}, f)
      }
    } else if (!this.authOpt.sso && this.authOpt.popup) {
      auth0Client.client.loginWithResourceOwner({...options, ...this.authOpt, ...authParams}, f)
    } else if (this.authOpt.popup) {
      auth0Client.popup.login({...options, ...this.authOpt, ...authParams}, f)
    } else {
      auth0Client.redirect.login({...options, ...this.authOpt, ...authParams}, f);
    }
  }

  signOut(query) {
    this.client.logout(query);
  }

  signUp(options, cb) {
    const { popup, sso } = this.authOpt;
    const { autoLogin } = options;

    delete options.autoLogin;

    const popupHandler = (autoLogin && popup) ? this.client.popup.preload() : null;

    this.client.signup(options, (err, result) => cb(err, result, popupHandler) );
  }

  resetPassword(options, cb) {
    this.client.changePassword(options, cb);
  }

  startPasswordless(options, cb) {
    this.client.startPasswordless(options, err => cb(normalizeError(err)));
  }

  parseHash(hash = '') {
    return this.client.parseHash(decodeURIComponent(hash));
  }

  getUserInfo(token, callback) {
    return this.client.client.userInfo(token, callback);
  }

  getSSOData(...args) {
    return this.client.client.getSSOData(...args);
  }

  getUserCountry(cb) {
    return this.client.getUserCountry(cb);
  }
}

export default Auth0LegacyAPIClient;