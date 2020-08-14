# Queue

This queue was designed with fairness in mind as there complaints of releases not being fair. There was a requirement for very flexible scalabilty, hence we chose [Cloudflare Workers®](https://workers.cloudflare.com/) to handle the intense load. This repository only contains the server-side API implementation but it is fairly easy to write your own frontend in something like React, Vue or Angular etc... We also had to prevent bot spam on the queue so we chose reCAPTCHA v3 and enforced low ratelimits on Cloudflare per IP to prevent spammers.

## Prerequisites

- Cloudflare Workers® Bundled (You will need KV access) to handle the actual service
- An Azure Cosmos DB to handle sessions
- A Shopify Store with a private application with the following scopes `read_products,write_customers,write_draft_orders` to create orders which customers can checkout on
- A Discord bot to handle login
- A Sentry account for logging exceptions
- A Google account to create reCAPTCHA v3 sitekeys

## Design

This queue works by generating two tickets when `ticketGeneration` is live.

A single server ticket which is essentially a random number that was securely generated. It uses the base `difficulty` and is divided by the `score` of the given user to create a random number and then the `difficulty` is stored in the session along with this ticket. Banned users, or users detected with the simple burner algorithm will have their score either lowered or set to zero. Having a zero score is never revealed to the user as it would be help a willing attacker to game the system. The algorithm is public, so you probably shouldn't use the same one that is currently in the queue.

Every successful poll (A valid reCAPTCHA v3 token and a non zero score) when the sale is live, a client ticket is generated again securely by dividing by the securely generated random number multiplied by the session stored `difficulty`. If it matches the server ticket and the item quantity for the item on Shopify is more than zero, a checkout is generated and then it awaits for the user to submit their address. If a user decides to submit invalid v3 reCAPTCHA their score is decreased so the chance for them to get through the queue is increased.

This current setup with a Cosmos DB instance with the RU/s (request units per second) set to max has handled around 2000 requests per second (with around half being poll requests) per the Cloudflare analytics. A bottleneck may arise from reCAPTCHA as they may have a ratelimit at roughly [1000 calls per second](https://developers.google.com/recaptcha/docs/faq#are-there-any-qps-or-daily-limits-on-my-use-of-recaptcha) however this can be countered by lowering the poll interval.

The theoretical sellout time of your item should be `(Time before sale is live) + (Quantity * Poll Interval (in seconds))` as on average one user should get through the queue on every poll interval after the sale is live.

## Setup

- Init a wrangler project with `wrangler generate queue https://github.com/afraidlabs/workers-queue`
- Setup KV namespaces
  - `QueueKV` records configuration for the queue itself
  - `CheckoutKV` records all potential checkouts created (Shopify Draft Orders)
- Setup enviornment variables
  - `COSMOSDB_DB_ID` should be the Cosmos DB database name
  - `COSMOSDB_COLL_ID` should be the Cosmos DB database column name
  - `COSMOSDB_URL` should be the Cosmos DB Endpoint
  - `DISCORD_CLIENT_ID` should be the Discord bot's client ID
  - `SHOPIFY_HOST` should be the Shopify store's hostname
  - `SENTRY_DSN` should be a Sentry DSN
- Setup environment [secrets](https://developers.cloudflare.com/workers/tooling/wrangler/secrets/)
  - `HMAC_SECRET` should be 64 bytes of CSPRNG encoded in hex
  - `COSMOSDB_SECRET` should be the primary key of the Cosmos DB previously specified
  - `SHOPIFY_ACCESS_TOKEN` should be an access token with the correct scopes as stated above
  - `DISCORD_CLIENT_SECRET` should be the Discord bot's client secret
- Set up the `config` key in the `QueueKV` namespace

    ```javascript
    {
        "captcha": {
            "action": "queue", // reCAPTCHA Action
            "siteKey": "6LePO_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", // reCAPTCHA siteKey
            "secretKey": "6LePO_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" // reCAPTCHA secretKey
        },
        "checkout": {
            "expiry": 900, // Checkout session lifetime in seconds
            "productId": 0000000000000, // Shopify product ID
            "cookieName": "example_c" // Checkout cookie name
        },
        "discord": {
            "superUsers": [
                "xxxxxxxxxxxxxxxxxx" // Users which can bypass a disabled queue
            ],
            "bannedUsers": [], // Banned users
            "bannedGuilds": [] // Banned Discord guilds
        },
        "queue": {
            "enabled": true, // Whether the queue is enabled
            "saleStart": 1591034480, // The timestamp in seconds for when the queue should start randomly choosing whether to let users through
            "difficulty": -1, // Set this to the number of people in the queue through the Cloudflare KV API, this is the base chance for a user getting through the queue
            "pollInterval": 5000, // How often the browser should poll
            "saleComplete": true, // Whether the sale is complete
            "ticketGeneration": true // Should the queue generate tickets, this determines the user's chance for the entirety of the queue
        },
        "session": {
            "expiry": 900, // User session lifetime in seconds
            "enabled": false, // Whether people should be able to login to the queue
            "cookieName": "example_u" // Session cookie name
        }
    }
    ```

- Setup the `messages` key in the `QueueKV` namespace with any messages you want, it should just be an array of strings

    ```javascript
    [
        "HOLD TIGHT AS WE FILTER OUT BOTS", // Lies inspired by adidas
        "SIT BACK AND RELAX WHILE YOU ENJOY YOUR L"
    ]
    ```

- Setup a queue monitor script, I have provided one below but requires a few dependencies and some of the same environment variables

    ```typescript
    import dotenv from 'dotenv';
    import axios, { Method } from 'axios';
    import { CosmosClient } from '@azure/cosmos';

    dotenv.config();

    const client = new CosmosClient({
        endpoint: process.env.COSMOSDB_ENDPOINT!,
        key: process.env.COSMOSDB_MASTERKEY!,
    });

    export const sessions = client
        .database(process.env.COSMOSDB_DATABASE!)
        .container(process.env.COSMOSDB_CONTAINER!);

    async function main() {
        await monitor();
    }

    interface Config {
        captcha: {
            action: string;
            siteKey: string;
            secretKey: string;
        };
        checkout: {
            expiry: number;
            productId: number;
            cookieName: string;
        };
        discord: {
            superUsers: string[];
            bannedUsers: string[];
            bannedGuilds: string[];
        };
        queue: {
            enabled: boolean;
            saleStart: number;
            difficulty: number;
            pollInterval: number;
            saleComplete: boolean;
            ticketGeneration: boolean;
        };
        session: {
            expiry: number;
            enabled: boolean;
            cookieName: string;
        };
    }

    interface Count {
        users: number;
        charge: number;
    }

    const sleep = async (ms: number) =>
        new Promise((resolve) => setTimeout(resolve, ms));

    export const currentTime = () => Math.floor(Date.now() / 1000);

    const TicketStart = currentTime() + 120;
    const SaleStart = currentTime() + 180;

    async function fetchUserCount(): Promise<Count> {
        const queryResponse = await sessions.items
            .query<number>(
                `SELECT VALUE COUNT(1) FROM c WHERE c.expiry > ${Math.floor(Date.now() / 1000)}`
            )
            .fetchAll();

        return {
            users: queryResponse.resources[0],
            charge: queryResponse.requestCharge,
        };
    }

    async function pullConfig(): Promise<Config | undefined> {
        const opts = {
            url: `https://api.cloudflare.com/client/v4/accounts/${process.env.CF_ACCOUNT_ID}/storage/kv/namespaces/${process.env.CF_NAMESPACE_ID}/values/config`,
            headers: {
                Authorization: `Bearer ${process.env.CF_AUTHORIZATION}`,
            },
        };

        try {
            const response = await axios(opts);
            return response.data;
        } catch (err) {
            console.log(err.message);
        }
    }

    async function writeConfig(config: Config) {
        const opts = {
            url: `https://api.cloudflare.com/client/v4/accounts/${process.env.CF_ACCOUNT_ID}/storage/kv/namespaces/${process.env.CF_NAMESPACE_ID}/values/config`,
            method: 'PUT' as Method,
            headers: {
                Authorization: `Bearer ${process.env.CF_AUTHORIZATION}`,
            },
            data: JSON.stringify(config, null, 4),
        };

        await axios(opts);
    }

    async function monitor() {
        console.log(
            `Configured Params - ${process.env
                .COSMOSDB_ENDPOINT!} - Ticket Start @ ${new Date(
                TicketStart * 1000
            ).toISOString()} - Sale Start @ ${new Date(
                SaleStart * 1000
            ).toISOString()}`
        );
        while (true) {
            const config = await pullConfig();

            if (!config) {
                continue;
            }

            const count = await fetchUserCount();
            const userCount = count.users;

            console.log(
                `${new Date().toISOString()} Current User Count ${userCount} - Current Difficulty ${
                    config.queue.difficulty
                } - Charge ${count.charge} RU`
            );

            if (config.queue.difficulty !== (userCount - 1 || 1)) {
                config.queue.difficulty = userCount - 1 || 1;
                console.log(
                    `${new Date().toISOString()} Updated Difficulty - ${
                        config.queue.difficulty
                    }`
                );
            }

            if (!config.queue.ticketGeneration && currentTime() >= TicketStart) {
                config.queue.ticketGeneration = true;
                console.log(
                    `${new Date().toISOString()} Enabled Ticket Generation`
                );
            }

            if (config.queue.saleStart === -1) {
                config.queue.saleStart = SaleStart;
                console.log(
                    `${new Date().toISOString()} Starting Sale @ - ${new Date(
                        SaleStart * 1000
                    ).toISOString()}`
                );
            }

            await writeConfig(config);

            await sleep(10000);
        }
    }

    main();
    ```

- Finally, setup your frontend and watch the world burn.

## License

The code in this repository is available under the MIT license, see the LICENSE file.
