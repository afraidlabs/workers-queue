import { KVNamespace } from '@cloudflare/workers-types';

declare global {
    const QueueKV: KVNamespace;
    const CheckoutKV: KVNamespace;
    const SENTRY_DSN: string;
    const HMAC_SECRET: string;
    const COSMOSDB_DB_ID: string;
    const COSMOSDB_COLL_ID: string;
    const COSMOSDB_URL: string;
    const COSMOSDB_SECRET: string;
    const SHOPIFY_HOST: string;
    const SHOPIFY_ACCESS_TOKEN: string;
    const DISCORD_CLIENT_ID: string;
    const DISCORD_CLIENT_SECRET: string;
}
