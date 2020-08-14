import { CosmosClient } from '@cfworker/cosmos';
import { DiscordUser, DiscordGuild } from './discord';
import { Poll, ClientTicket } from './queue';
import { Config, pullConfig, currentTime, sleep, CLIENT_IP_HEADER, USER_AGENT_HEADER, Unauthorized } from './handler';

import { Checkout } from './checkout';

export const HMAC_KEY = crypto.subtle.importKey(
    'raw',
    Buffer.from(HMAC_SECRET, 'hex'),
    {
        name: 'HMAC',
        hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
);

const SignedTokenParams = ['exp', 'discord', 'session', 'hmac'];

const client = new CosmosClient({
    endpoint: COSMOSDB_URL,
    masterKey: COSMOSDB_SECRET,
    dbId: COSMOSDB_DB_ID,
    collId: COSMOSDB_COLL_ID,
});

interface BrowserClient {
    clientIP: string;
    userAgent: string;
}

export interface Session {
    id: string;
    ttl: number;
    score: number;
    expiry: number;
    ticket: number;
    difficulty: number;
    client: BrowserClient;
    discord: DiscordUser;
    checkout?: Checkout;
    loginTime: string;
    lastPollTime: number;
    failedPolls: Poll[];
    successfulPolls: Poll[];
    clientTickets: ClientTicket[];
}

interface SessionObject {
    valid: boolean;
    expiry?: number;
    discord?: string;
    token?: string;
    hmac?: string;
}

interface UserResponse {
    discord: string;
    avatar: string;
}

interface UserAgent {
    device: Device;
}

interface Device {
    is_mobile_device: boolean;
    type: string;
    brand: string;
    brand_code: string;
    brand_url: string;
    name: string;
}

export function setCookie(
    response: Response,
    cookieName: string,
    cookieValue: string,
    expiry: number,
    httpOnly: boolean = true,
) {
    const cookie = [
        `${cookieName}=${cookieValue}`,
        'Secure',
        httpOnly ? 'HttpOnly' : null,
        'Path=/',
        `Max-Age=${expiry}`,
        'SameSite=Strict',
    ]
        .filter((item) => item)
        .join('; ');

    response.headers.append('Set-Cookie', cookie);
}

export function setCookieRemoval(response: Response, cookieName: string) {
    const cookie = [`${cookieName}=-1`, 'Path=/', `Max-Age=0`, 'SameSite=Strict'].filter((item) => item).join('; ');
    response.headers.append('Set-Cookie', cookie);
}

export async function existingSessions(user: DiscordUser, retryLimit: number = 5): Promise<Session[] | undefined> {
    const query = `SELECT * FROM ${COSMOSDB_COLL_ID} x WHERE x.discord.id = @discordId AND x.expiry > ${currentTime()}`;
    const parameters = [{ name: '@discordId', value: user.id }];
    const res = await client.queryDocuments<Session>({
        query,
        parameters,
        enableCrossPartition: true,
    });

    switch (res.status) {
        case 200:
            const docs = await res.json();
            return docs;
        case 429:
            await sleep(1000);
        default:
            if (retryLimit > 0) {
                return existingSessions(user, (retryLimit -= 1));
            }
    }
}

function createSessionToken(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    return Buffer.from(bytes).toString('base64').replace(/=/g, '').replace(/\//g, '_').replace(/\+/g, '-');
}

export async function createSession(
    request: Request,
    user: DiscordUser,
    guilds: DiscordGuild[],
): Promise<[string, number]> {
    let score = 1;

    switch (guilds.length) {
        case 0 || 1:
            score = 0;
            break;
        case 2 || 3:
            score = score / 25;
            break;
        case 4:
            score = score / 10;
            break;
    }

    if (!user.verified) {
        score = 0;
    }

    if (parseInt(user.discriminator, 10) % 5 === parseInt(user.avatar, 10)) {
        score = score / 20;
    }

    const config = await pullConfig();

    const userGuilds = new Set(guilds.map((guild) => guild.id));
    const bannedUsers = new Set(config.discord.bannedUsers);

    if (bannedUsers.has(user.id)) {
        score = 0;
    }

    for (const guild of config.discord.bannedGuilds) {
        if (userGuilds.has(guild)) {
            score = 0;
        }
    }

    const checkout = await CheckoutKV.get(user.id);

    if (checkout) {
        score = 0;
    }

    // ////////////////////
    // /// Mobile Only ///
    // ////////////////////

    // const response = await fetch(
    //     `https://api.userstack.com/api/detect?access_key=<APIKey>&ua=${request.headers.get(
    //         'User-Agent',
    //     )}&fields=device`,
    // );

    // switch (response.status) {
    //     case 200:
    //         const deviceUA: UserAgent = await response.json();
    //         if (!deviceUA.device.is_mobile_device) {
    //             score = 0
    //         }
    //         break;
    // }

    const sessionToken = createSessionToken();

    const currentTimestamp = new Date();

    const session: Session = {
        id: sessionToken,
        ttl: 86400,
        expiry: config.session.expiry + currentTime(),
        score,
        ticket: -1,
        difficulty: -1,
        client: {
            clientIP: request.headers.get(CLIENT_IP_HEADER)!,
            userAgent: request.headers.get(USER_AGENT_HEADER)!,
        },
        discord: user,
        loginTime: currentTimestamp.toISOString(),
        lastPollTime: -1,
        clientTickets: [],
        failedPolls: [],
        successfulPolls: [],
    };

    const sessionExpiry = await writeSession(session);

    return [await signSession(request, session, sessionToken, session.expiry), sessionExpiry];
}

async function writeSession(session: Session): Promise<number> {
    const response = await client.createDocument<Session>({
        isUpsert: true,
        document: session,
        partitionKey: session.discord.id,
    });

    const doc = await response.json();
    return doc.expiry - currentTime();
}

async function readSession(sessionObject: SessionObject): Promise<Session | undefined> {
    const response = await client.getDocument<Session>({
        docId: sessionObject.token!,
        partitionKey: sessionObject.discord!,
    });

    switch (response.status) {
        case 200:
            const doc = await response.json();
            if (doc.expiry === sessionObject.expiry) {
                return doc;
            }
            break;
        case 404:
            // Shouldn't happen (Check Expiry)
            break;
    }
}

async function signSession(
    request: Request,
    session: Session,
    sessionToken: string,
    sessionExpiry: number,
): Promise<string> {
    const encoder = new TextEncoder();

    const data = new Uint8Array([
        ...encoder.encode(`${sessionExpiry}`),
        ...encoder.encode(session.discord.id),
        ...encoder.encode(sessionToken),
        ...encoder.encode(request.headers.get(CLIENT_IP_HEADER)!),
        ...encoder.encode(request.headers.get(USER_AGENT_HEADER)!),
    ]);

    const hmac = await crypto.subtle.sign('HMAC', await HMAC_KEY, data);

    const signedSession = new URLSearchParams();

    [`${sessionExpiry}`, session.discord.id, sessionToken, Buffer.from(hmac).toString('hex')].forEach(
        (param, index) => {
            signedSession.set(SignedTokenParams[index], param);
        },
    );

    return signedSession.toString();
}

export function getCookie(request: Request, name: string): string | undefined {
    const cookieName = `${name}=`;
    const cookieString = request.headers.get('Cookie');

    if (cookieString) {
        const decodedCookie = decodeURIComponent(cookieString);
        const cookieArray = decodedCookie.split(';');

        for (let cookie of cookieArray) {
            while (cookie.charAt(0) === ' ') {
                cookie = cookie.substring(1);
            }
            if (cookie.indexOf(cookieName) === 0) {
                return cookie.substring(cookieName.length, cookie.length);
            }
        }
    }
}

export async function validateSession(request: Request, config: Config): Promise<SessionObject> {
    const signedSession = getCookie(request, config.session.cookieName);
    const signedSessionParams = new URLSearchParams(signedSession);

    if (
        signedSession &&
        signedSession.length <= 256 &&
        SignedTokenParams.every((param) => signedSessionParams.has(param))
    ) {
        const encoder = new TextEncoder();
        const [exp, discord, token, hmac]: string[] = SignedTokenParams.map((param) => signedSessionParams.get(param)!);

        const data = new Uint8Array([
            ...encoder.encode(exp),
            ...encoder.encode(discord),
            ...encoder.encode(token),
            ...encoder.encode(request.headers.get(CLIENT_IP_HEADER)!),
            ...encoder.encode(request.headers.get(USER_AGENT_HEADER)!),
        ]);

        const valid = await crypto.subtle.verify('HMAC', await HMAC_KEY, Buffer.from(hmac, 'hex'), data);
        const expiry = parseInt(exp, 10);

        return {
            valid: valid && expiry > currentTime(),
            expiry,
            discord,
            token,
            hmac,
        };
    }

    return { valid: false };
}

export async function pullSession(request: Request, config: Config): Promise<[SessionObject, Session | undefined]> {
    const sessionObject = await validateSession(request, config);

    if (sessionObject.valid) {
        const session = await readSession(sessionObject);
        sessionObject.valid = session ? true : false;
        return [sessionObject, session];
    }

    return [sessionObject, undefined];
}

export async function deleteSession(session: Session): Promise<boolean> {
    const response = await client.deleteDocument({ docId: session.id, partitionKey: session.discord.id });

    if (response.status === 204) {
        return true;
    }

    return false;
}

export async function updateSession(request: Request, config: Config, session: Session): Promise<[string, number]> {
    session.expiry = currentTime() + config.session.expiry;
    const sessionExpiry = await writeSession(session);
    return [await signSession(request, session, session.id, session.expiry), sessionExpiry];
}

export async function handleUser(request: Request, url: URL): Promise<Response> {
    const config = await pullConfig();
    const [sessionObj, session] = await pullSession(request, config);

    if (sessionObj.valid && session) {
        const user: UserResponse = {
            discord: `${session.discord.username}#${session.discord.discriminator}`,
            avatar: session.discord.avatar,
        };

        const response = new Response(JSON.stringify(user), {
            headers: {
                'Content-Type': 'application/json',
            },
        });

        const [signedSession, sessionExpiry] = await updateSession(request, config, session);
        setCookie(response, config.session.cookieName, signedSession, sessionExpiry);
        return response;
    }

    return Unauthorized();
}
