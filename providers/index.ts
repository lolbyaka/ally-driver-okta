import type { ApplicationContract } from '@ioc:Adonis/Core/Application'

export default class OktaDriverProvider {
  constructor(protected app: ApplicationContract) {}

  public async boot() {
    const Ally = this.app.container.resolveBinding('Adonis/Addons/Ally')
    const { OktaDriver } = await import('../src/Okta')

    Ally.extend('Okta', (_, __, config, ctx) => {
      return new OktaDriver(ctx, config)
    })
  }
}
