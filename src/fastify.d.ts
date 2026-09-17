// Type-only augmentation for the request decorators set in api-key-auth.js. No runtime code.
import 'fastify';

declare module 'fastify' {
  interface FastifyRequest {
    apiKeyId: string;
    apiKeyRole: string | undefined;
    apiKeyScopes: string[] | null;
  }
}
