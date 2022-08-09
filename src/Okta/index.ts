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

import type { AllyUserContract } from '@ioc:Adonis/Addons/Ally'
import type { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'
import { Oauth2Driver, ApiRequest } from '@adonisjs/ally/build/standalone'
import OktaJwtVerifier from '@okta/jwt-verifier'
import _ from 'lodash'
import AllyUser, { UserFields } from '../helpers/AllyUser'

export type OktaDriverAccessToken = {
  token: string
  type: 'bearer'
}

export type OktaDriverScopes = 'openid' | 'profile' | 'email'

export type OktaDriverConfig = {
  driver: 'Okta'
  clientId: string
  callbackUrl: string
  clientSecret: string
  issuer: string
  domain: string
  scopes: OktaDriverScopes[]
}

export type UserInfo = {
  sub: string
  name: string
  locale: string
  email: string
  preferred_username: string
  given_name: string
  family_name: string
  zoneinfo: string
  email_verified: boolean
}

/**
 * Driver implementation. It is mostly configuration driven except the user calls
 */
export class OktaDriver extends Oauth2Driver<OktaDriverAccessToken, OktaDriverScopes> {
  /**
   * The URL for the redirect request. The user will be redirected on this page
   * to authorize the request.
   *
   * Do not define query strings in this URL.
   */
  protected authorizeUrl = ''

  /**
   * The URL to hit to exchange the authorization code for the access token
   *
   * Do not define query strings in this URL.
   */
  protected accessTokenUrl = ''

  /**
   * The URL to hit to get the user details
   *
   * Do not define query strings in this URL.
   */
  protected userInfoUrl = ''

  /**
   * The param name for the authorization code. Read the documentation of your oauth
   * provider and update the param name to match the query string field name in
   * which the oauth provider sends the authorization_code post redirect.
   */
  protected codeParamName = 'code'

  /**
   * The param name for the error. Read the documentation of your oauth provider and update
   * the param name to match the query string field name in which the oauth provider sends
   * the error post redirect
   */
  protected errorParamName = 'error'

  /**
   * Cookie name for storing the CSRF token. Make sure it is always unique. So a better
   * approach is to prefix the oauth provider name to `oauth_state` value. For example:
   * For example: "facebook_oauth_state"
   */
  protected stateCookieName = 'OktaDriver_oauth_state'

  /**
   * Parameter name to be used for sending and receiving the state from.
   * Read the documentation of your oauth provider and update the param
   * name to match the query string used by the provider for exchanging
   * the state.
   */
  protected stateParamName = 'state'

  /**
   * Parameter name for sending the scopes to the oauth provider.
   */
  protected scopeParamName = 'scope'

  /**
   * The separator indentifier for defining multiple scopes
   */
  protected scopesSeparator = ','

  protected issuer = ''
  protected domain = ''
  protected clientId = ''

  constructor(ctx: HttpContextContract, public config: OktaDriverConfig) {
    super(ctx, config)

    /**
     * Extremely important to call the following method to clear the
     * state set by the redirect request.
     *
     * DO NOT REMOVE THE FOLLOWING LINE
     */
    this.loadState()

    this.domain = config.domain
    this.issuer = config.issuer
    this.clientId = config.clientId
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
  public accessDenied() {
    return this.ctx.request.input('error') === 'user_denied'
  }

  public getCode(): string | null {
    return this.ctx.request.input(this.codeParamName, null)
  }

  protected buildAllyUser(userProfile, accessTokenResponse) {
    const allyUserBuilder = new AllyUser()
    const expires = _.get(accessTokenResponse, 'expiresAt')

    allyUserBuilder
      .setOriginal(userProfile)
      .setFields(
        userProfile.sub,
        userProfile.given_name,
        userProfile.family_name,
        userProfile.email,
        null,
        userProfile.email_verified ? 'verified' : 'unverified'
      )
      .setToken(accessTokenResponse.accessToken, null, null, expires ? Number(expires) : null)

    const user: UserFields = allyUserBuilder.toJSON()

    return user
  }

  /**
   * Get the user details by query the provider API. This method must return
   * the access token and the user details both. Checkout the google
   * implementation for same.
   *
   * https://github.com/adonisjs/ally/blob/develop/src/Drivers/Google/index.ts#L191-L199
   */
  public async user(
    _callback?: (request: ApiRequest) => void
  ): Promise<AllyUserContract<OktaDriverAccessToken>> {
    const accessTokenResponse = this.ctx.request.input('accessToken')
    const errorMessage = 'Okta login failed'

    if (!accessTokenResponse) throw new Error(errorMessage)

    const audience = this.ctx.request.input('oktaAud') || 'api://default'

    if (
      this.ctx.request.input('oktaDomain') &&
      this.ctx.request.input('oktaClientId') &&
      this.ctx.request.input('oktaIssuer')
    ) {
      this.issuer = this.ctx.request.input('oktaIssuer')
      this.domain = this.ctx.request.input('oktaDomain')
      this.clientId = this.ctx.request.input('oktaClientId')
    }

    try {
      const oktaJwtVerifier = new OktaJwtVerifier({
        issuer: this.issuer,
        clientId: this.clientId,
        assertClaims: {
          cid: this.clientId,
          aud: audience,
        },
      })

      await oktaJwtVerifier.verifyAccessToken(accessTokenResponse.value, audience)

      const userProfile = await this.getUserInfo(accessTokenResponse.value)

      return {
        ...userProfile,
        token: accessTokenResponse.value,
      }
    } catch (e) {
      throw new Error(errorMessage)
    }
  }

  /**
   * Returns the HTTP request with the authorization header set
   */
  protected getAuthenticatedRequest(url: string, token: string) {
    const request = this.httpClient(url)
    request.header('Authorization', `Bearer ${token}`)
    request.header('Accept', 'application/json')
    request.header('x-li-format', 'json')
    request.parseAs('json')
    return request
  }

  protected async getUserInfo(accessToken: string, callback?: (request: ApiRequest) => void) {
    // User Info
    const userRequest = this.getAuthenticatedRequest(`${this.issuer}/v1/userinfo`, accessToken)

    const accessTokenResponse = {
      accessToken,
    }

    if (typeof callback === 'function') {
      callback(userRequest)
    }

    const userBody = await userRequest.get()

    return this.buildAllyUser(userBody, accessTokenResponse)
  }

  public async userFromToken(
    accessToken: string
  ): Promise<AllyUserContract<OktaDriverAccessToken>> {
    const user: any = {}

    return {
      ...user,
      token: { token: accessToken, type: 'bearer' as const },
    }
  }
}
