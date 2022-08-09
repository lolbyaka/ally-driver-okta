/// <reference types="@adonisjs/ally" />
/// <reference types="@adonisjs/http-server/build/adonis-typings" />
/// <reference types="@adonisjs/ally" />
import type { AllyUserContract } from '@ioc:Adonis/Addons/Ally';
import type { HttpContextContract } from '@ioc:Adonis/Core/HttpContext';
import { Oauth2Driver, ApiRequest } from '@adonisjs/ally/build/standalone';
import { UserFields } from '../helpers/AllyUser';
export declare type OktaDriverAccessToken = {
    token: string;
    type: 'bearer';
};
export declare type OktaDriverScopes = 'openid' | 'profile' | 'email';
export declare type OktaDriverConfig = {
    driver: 'Okta';
    clientId: string;
    callbackUrl: string;
    clientSecret: string;
    issuer: string;
    domain: string;
    scopes: OktaDriverScopes[];
};
export declare type UserInfo = {
    sub: string;
    name: string;
    locale: string;
    email: string;
    preferred_username: string;
    given_name: string;
    family_name: string;
    zoneinfo: string;
    email_verified: boolean;
};
/**
 * Driver implementation. It is mostly configuration driven except the user calls
 */
export declare class OktaDriver extends Oauth2Driver<OktaDriverAccessToken, OktaDriverScopes> {
    config: OktaDriverConfig;
    /**
     * The URL for the redirect request. The user will be redirected on this page
     * to authorize the request.
     *
     * Do not define query strings in this URL.
     */
    protected authorizeUrl: string;
    /**
     * The URL to hit to exchange the authorization code for the access token
     *
     * Do not define query strings in this URL.
     */
    protected accessTokenUrl: string;
    /**
     * The URL to hit to get the user details
     *
     * Do not define query strings in this URL.
     */
    protected userInfoUrl: string;
    /**
     * The param name for the authorization code. Read the documentation of your oauth
     * provider and update the param name to match the query string field name in
     * which the oauth provider sends the authorization_code post redirect.
     */
    protected codeParamName: string;
    /**
     * The param name for the error. Read the documentation of your oauth provider and update
     * the param name to match the query string field name in which the oauth provider sends
     * the error post redirect
     */
    protected errorParamName: string;
    /**
     * Cookie name for storing the CSRF token. Make sure it is always unique. So a better
     * approach is to prefix the oauth provider name to `oauth_state` value. For example:
     * For example: "facebook_oauth_state"
     */
    protected stateCookieName: string;
    /**
     * Parameter name to be used for sending and receiving the state from.
     * Read the documentation of your oauth provider and update the param
     * name to match the query string used by the provider for exchanging
     * the state.
     */
    protected stateParamName: string;
    /**
     * Parameter name for sending the scopes to the oauth provider.
     */
    protected scopeParamName: string;
    /**
     * The separator indentifier for defining multiple scopes
     */
    protected scopesSeparator: string;
    protected issuer: string;
    protected domain: string;
    protected clientId: string;
    constructor(ctx: HttpContextContract, config: OktaDriverConfig);
    /**
     * Optionally configure the authorization redirect request. The actual request
     * is made by the base implementation of "Oauth2" driver and this is a
     * hook to pre-configure the request.
     */
    /**
     * Optionally configure the access token request. The actual request is made by
     * the base implementation of "Oauth2" driver and this is a hook to pre-configure
     * the request
     */
    /**
     * Update the implementation to tell if the error received during redirect
     * means "ACCESS DENIED".
     */
    accessDenied(): boolean;
    getCode(): string | null;
    protected buildAllyUser(userProfile: any, accessTokenResponse: any): UserFields;
    /**
     * Get the user details by query the provider API. This method must return
     * the access token and the user details both. Checkout the google
     * implementation for same.
     *
     * https://github.com/adonisjs/ally/blob/develop/src/Drivers/Google/index.ts#L191-L199
     */
    user(_callback?: (request: ApiRequest) => void): Promise<AllyUserContract<OktaDriverAccessToken>>;
    /**
     * Returns the HTTP request with the authorization header set
     */
    protected getAuthenticatedRequest(url: string, token: string): ApiRequest;
    protected getUserInfo(accessToken: string, callback?: (request: ApiRequest) => void): Promise<UserFields>;
    userFromToken(accessToken: string): Promise<AllyUserContract<OktaDriverAccessToken>>;
}
