import { captureError } from '@cfworker/sentry';
import { Router, Method } from 'tiny-request-router';
import { handleLogin, handleDiscord } from './discord';
import { handleUser } from './session';
import { handleConfig, handlePoll } from './queue';
import { handleAddress } from './checkout';

export interface Config {
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

export const USER_AGENT_HEADER = 'User-Agent';
export const CLIENT_IP_HEADER = 'CF-Connecting-IP';

export const currentTime = () => Math.floor(Date.now() / 1000);
export const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

type Handler = (request: Request, url: URL, event: FetchEvent) => Promise<Response>;

const router = new Router<Handler>();

router.get('/api/user', handleUser); 
router.get('/api/config', handleConfig); 
router.get('/api/login', handleLogin);
router.get('/api/discord', handleDiscord);
router.post('/api/poll', handlePoll);
router.put('/api/submit_address', handleAddress);

export const NotFound = async () =>
    new Response(
        JSON.stringify({
            error: 'Not Found',
        }),
        {
            status: 404,
            headers: {
                'Content-Type': 'application/json',
            },
        },
    );

export const BadRequest = async () =>
    new Response(
        JSON.stringify({
            error: 'Bad Request',
        }),
        {
            status: 400,
            headers: {
                'Content-Type': 'application/json',
            },
        },
    );

export const Unauthorized = async () =>
    new Response(
        JSON.stringify({
            error: 'Unauthorized',
        }),
        {
            status: 401,
            headers: {
                'Content-Type': 'application/json',
            },
        },
    );

export const Forbidden = async () =>
    new Response(
        JSON.stringify({
            error: 'Forbidden',
        }),
        {
            status: 403,
            headers: {
                'Content-Type': 'application/json',
            },
        },
    );

export const ServerError = async (eventId?: string) =>
    new Response(
        JSON.stringify({
            error: 'Internal Server Error',
            eventId,
        }),
        {
            status: 500,
            headers: {
                'Content-Type': 'application/json',
            },
        },
    );

export async function handleRequest(event: FetchEvent): Promise<Response> {
    const request = event.request;
    const url = new URL(request.url);

    if (!request.headers.get('User-Agent')) {
        return Forbidden();
    }

    const match = await router.match(request.method as Method, url.pathname);

    try {
        if (match) {
            const response = match.handler(request, url, event);
            return await response;
        }

        return NotFound();
    } catch (error) {
        if (error instanceof SyntaxError) {
            return BadRequest();
        }

        const { event_id, promise } = captureError(
            SENTRY_DSN,
            url.host.includes('queue-dev') ? 'development' : url.host.includes('queue-stg') ? 'staging' : 'production',
            error,
            event.request,
            undefined,
        );

        event.waitUntil(promise);

        return ServerError(event_id);
    }
}

export async function pullConfig(): Promise<Config> {
    const config = await QueueKV.get('config');
    return JSON.parse(config!);
}
