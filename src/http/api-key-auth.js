import { ApiKeyAuth as CoreApiKeyAuth } from '@atc-web/service-core/auth';

/** @typedef {import('../types.js').ApiKey} ApiKey */

/**
 * Bearer API-key authentication for Fastify — the calling-backend key, not an end user's session
 * or JWT (those stay entirely local; nothing about login, tokens or passwords moves here). Thin
 * wrapper over service-core's `ApiKeyAuth`: no role model (these keys have never had one),
 * `decorate` attaches only `request.apiKeyId`, `identify()` keeps returning the id string.
 */
export class ApiKeyAuth {
  /** @param {ApiKey[]} apiKeys */
  constructor(apiKeys) {
    this.core = new CoreApiKeyAuth(apiKeys, {
      decorate: (request, key) => { request.apiKeyId = key.id; },
    });
  }

  /** Fastify `onRequest` hook. */
  get hook() {
    return this.core.hook;
  }

  /**
   * @param {string} secret Presented secret.
   * @returns {string|undefined} Matching key id.
   */
  identify(secret) {
    return this.core.identify(secret)?.id;
  }
}
