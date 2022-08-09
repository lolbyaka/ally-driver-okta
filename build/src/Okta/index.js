"use strict";
/*
|--------------------------------------------------------------------------
| Ally Oauth driver
|--------------------------------------------------------------------------
|
| This is a dummy implementation of the Oauth driver. Make sure you
|
| - Got through every line of code
| - Read every comment
|
*/
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.OktaDriver = void 0;
const standalone_1 = require("@adonisjs/ally/build/standalone");
const jwt_verifier_1 = __importDefault(require("@okta/jwt-verifier"));
const lodash_1 = __importDefault(require("lodash"));
const AllyUser_1 = __importDefault(require("../helpers/AllyUser"));
/**
 * Driver implementation. It is mostly configuration driven except the user calls
 */
class OktaDriver extends standalone_1.Oauth2Driver {
    constructor(ctx, config) {
        super(ctx, config);
        this.config = config;
        /**
         * The URL for the redirect request. The user will be redirected on this page
         * to authorize the request.
         *
         * Do not define query strings in this URL.
         */
        this.authorizeUrl = '';
        /**
         * The URL to hit to exchange the authorization code for the access token
         *
         * Do not define query strings in this URL.
         */
        this.accessTokenUrl = '';
        /**
         * The URL to hit to get the user details
         *
         * Do not define query strings in this URL.
         */
        this.userInfoUrl = '';
        /**
         * The param name for the authorization code. Read the documentation of your oauth
         * provider and update the param name to match the query string field name in
         * which the oauth provider sends the authorization_code post redirect.
         */
        this.codeParamName = 'code';
        /**
         * The param name for the error. Read the documentation of your oauth provider and update
         * the param name to match the query string field name in which the oauth provider sends
         * the error post redirect
         */
        this.errorParamName = 'error';
        /**
         * Cookie name for storing the CSRF token. Make sure it is always unique. So a better
         * approach is to prefix the oauth provider name to `oauth_state` value. For example:
         * For example: "facebook_oauth_state"
         */
        this.stateCookieName = 'OktaDriver_oauth_state';
        /**
         * Parameter name to be used for sending and receiving the state from.
         * Read the documentation of your oauth provider and update the param
         * name to match the query string used by the provider for exchanging
         * the state.
         */
        this.stateParamName = 'state';
        /**
         * Parameter name for sending the scopes to the oauth provider.
         */
        this.scopeParamName = 'scope';
        /**
         * The separator indentifier for defining multiple scopes
         */
        this.scopesSeparator = ',';
        this.issuer = '';
        this.domain = '';
        this.clientId = '';
        /**
         * Extremely important to call the following method to clear the
         * state set by the redirect request.
         *
         * DO NOT REMOVE THE FOLLOWING LINE
         */
        this.loadState();
        this.domain = config.domain;
        this.issuer = config.issuer;
        this.clientId = config.clientId;
        // this.callback = config.redirectUri
    }
    /**
     * Optionally configure the authorization redirect request. The actual request
     * is made by the base implementation of "Oauth2" driver and this is a
     * hook to pre-configure the request.
     */
    // protected configureRedirectRequest(request: RedirectRequest<OktaDriverScopes>) {}
    /**
     * Optionally configure the access token request. The actual request is made by
     * the base implementation of "Oauth2" driver and this is a hook to pre-configure
     * the request
     */
    // protected configureAccessTokenRequest(request: ApiRequest) {}
    /**
     * Update the implementation to tell if the error received during redirect
     * means "ACCESS DENIED".
     */
    accessDenied() {
        return this.ctx.request.input('error') === 'user_denied';
    }
    getCode() {
        return this.ctx.request.input(this.codeParamName, null);
    }
    buildAllyUser(userProfile, accessTokenResponse) {
        const allyUserBuilder = new AllyUser_1.default();
        const expires = lodash_1.default.get(accessTokenResponse, 'expiresAt');
        allyUserBuilder
            .setOriginal(userProfile)
            .setFields(userProfile.sub, userProfile.given_name, userProfile.family_name, userProfile.email, null, userProfile.email_verified ? 'verified' : 'unverified')
            .setToken(accessTokenResponse.accessToken, null, null, expires ? Number(expires) : null);
        const user = allyUserBuilder.toJSON();
        return user;
    }
    /**
     * Get the user details by query the provider API. This method must return
     * the access token and the user details both. Checkout the google
     * implementation for same.
     *
     * https://github.com/adonisjs/ally/blob/develop/src/Drivers/Google/index.ts#L191-L199
     */
    async user(_callback) {
        const accessTokenResponse = this.ctx.request.input('accessToken');
        const errorMessage = 'Okta login failed';
        if (!accessTokenResponse)
            throw new Error(errorMessage);
        const audience = this.ctx.request.input('oktaAud') || 'api://default';
        if (this.ctx.request.input('oktaDomain') && this.ctx.request.input('oktaClientId')) {
            this.issuer =
                this.ctx.request.input('oktaIssuer') ||
                    `https://${this.ctx.request.input('oktaDomain')}/oauth2/default`;
            this.domain = this.ctx.request.input('oktaDomain');
            this.clientId = this.ctx.request.input('oktaClientId');
        }
        try {
            const oktaJwtVerifier = new jwt_verifier_1.default({
                issuer: this.issuer,
                clientId: this.clientId,
                assertClaims: {
                    cid: this.clientId,
                    aud: audience,
                },
            });
            await oktaJwtVerifier.verifyAccessToken(accessTokenResponse.value, audience);
            const userProfile = await this.getUserInfo(accessTokenResponse.value);
            return {
                ...userProfile,
                token: accessTokenResponse.value,
            };
        }
        catch (e) {
            throw new Error(errorMessage);
        }
    }
    /**
     * Returns the HTTP request with the authorization header set
     */
    getAuthenticatedRequest(url, token) {
        const request = this.httpClient(url);
        request.header('Authorization', `Bearer ${token}`);
        request.header('Accept', 'application/json');
        request.header('x-li-format', 'json');
        request.parseAs('json');
        return request;
    }
    async getUserInfo(accessToken, callback) {
        // User Info
        const userRequest = this.getAuthenticatedRequest(`${this.issuer}/v1/userinfo`, accessToken);
        const accessTokenResponse = {
            accessToken,
        };
        if (typeof callback === 'function') {
            callback(userRequest);
        }
        const userBody = await userRequest.get();
        return this.buildAllyUser(userBody, accessTokenResponse);
    }
    async userFromToken(accessToken) {
        const user = {};
        return {
            ...user,
            token: { token: accessToken, type: 'bearer' },
        };
    }
}
exports.OktaDriver = OktaDriver;
