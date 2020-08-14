import { stringify } from 'querystring';
import {
    getCookie,
    setCookie,
    setCookieRemoval,
    existingSessions,
    createSession,
    pullSession,
    deleteSession,
} from './session';

import { ServerError, pullConfig, currentTime, sleep, Forbidden } from './handler';

const HomeRedirect = async () =>
    new Response(null, {
        status: 302,
        headers: {
            Location: '/',
        },
    });

export interface DiscordUser {
    id: string;
    username: string;
    avatar: string;
    discriminator: string;
    public_flags: number;
    flags: number;
    email: string;
    verified: boolean;
    locale: string;
    mfa_enabled: boolean;
    credentials?: Credentials;
}

export interface DiscordGuild {
    id: string;
    name: string;
    icon: string;
    owner: boolean;
    permissions: number;
}

interface Credentials {
    access_token: string;
    refresh_token: string;
    expires_at: number;
}

interface DiscordOAuth {
    access_token: string;
    token_type: string;
    expires_in: number;
    refresh_token: string;
    scope: string;
}

interface DiscordRatelimit {
    message: string;
    retry_after: number;
    global: boolean;
}

export async function handleLogin(request: Request, url: URL): Promise<Response> {
    const config = await pullConfig();
    const [sessionObj, session] = await pullSession(request, config);

    if (sessionObj.valid && session) {
        // Redirect Home
        return HomeRedirect();
    }

    const response = await redirectResponse(url);

    if (getCookie(request, config.session.cookieName)) {
        setCookieRemoval(response, config.session.cookieName);
    }

    return response;
}

export async function handleDiscord(request: Request, url: URL): Promise<Response> {
    const code = url.searchParams.get('code');

    if (code && code.length < 64) {
        const response = await fetch('https://discordapp.com/api/v6/oauth2/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: stringify({
                client_id: DISCORD_CLIENT_ID,
                client_secret: DISCORD_CLIENT_SECRET,
                grant_type: 'authorization_code',
                code,
                redirect_uri: `${url.origin}${url.pathname}`,
                scope: 'identify email connections guilds',
            }),
        });

        switch (response.status) {
            case 200:
                const config = await pullConfig();
                const credentials: DiscordOAuth = await response.json();
                const expiresAt = credentials.expires_in + currentTime();

                const [user, guilds] = await Promise.all([pullUser(credentials), pullUserGuilds(credentials)]);

                if (!user || !guilds) {
                    return ServerError();
                }

                const superUsers = new Set(config.discord.superUsers);

                if (!config.session.enabled && !superUsers.has(user.id)) {
                    return new Response(
                        JSON.stringify({
                            error: 'Session Exists',
                        }),
                        {
                            status: 409,
                        },
                    );
                }

                user.credentials = {
                    access_token: credentials.access_token,
                    refresh_token: credentials.refresh_token,
                    expires_at: expiresAt,
                };

                const sessions = await existingSessions(user);

                if (!sessions) {
                    return ServerError();
                }

                if (sessions.length > 0) {
                    for (const session of sessions) {
                        if (!(await deleteSession(session))) {
                            return ServerError();
                        }
                    }
                }

                const [signedSession, sessionExpiry] = await createSession(request, user, guilds);
                const redirect = await HomeRedirect();
                setCookie(redirect, config.session.cookieName, signedSession, sessionExpiry);

                return redirect;
            case 400 || 401:
                break;
            default:
                return ServerError();
        }
    }

    return handleLogin(request, url);
}

async function pullUser(credentials: DiscordOAuth, retryLimit: number = 5): Promise<DiscordUser | undefined> {
    const response = await fetch('https://discordapp.com/api/v6/users/@me', {
        method: 'GET',
        headers: {
            Authorization: `Bearer ${credentials.access_token}`,
        },
    });

    switch (response.status) {
        case 200:
            return response.json();
        case 429:
            const ratelimit: DiscordRatelimit = await response.json();
            await sleep(ratelimit.retry_after);
        default:
            if (retryLimit > 0) {
                return pullUser(credentials, (retryLimit -= 1));
            }
    }
}

async function pullUserGuilds(credentials: DiscordOAuth, retryLimit: number = 5): Promise<DiscordGuild[] | undefined> {
    const response = await fetch('https://discordapp.com/api/v6/users/@me/guilds', {
        method: 'GET',
        headers: {
            Authorization: `Bearer ${credentials.access_token}`,
        },
    });

    switch (response.status) {
        case 200:
            return response.json();
        case 429:
            const ratelimit: DiscordRatelimit = await response.json();
            await sleep(ratelimit.retry_after);
        default:
            if (retryLimit > 0) {
                return pullUserGuilds(credentials, (retryLimit -= 1));
            }
    }
}

async function redirectResponse(url: URL): Promise<Response> {
    return new Response(null, {
        status: 302,
        headers: {
            Location: encodeURI(
                `https://discordapp.com/api/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=https://${url.host}/api/discord&response_type=code&scope=identify email connections guilds`,
            ),
        },
    });
}
