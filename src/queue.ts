import { pullSession, updateSession, setCookie, Session } from './session';

import { stringify } from 'querystring';
import { Config, pullConfig, CLIENT_IP_HEADER, currentTime, Forbidden } from './handler';
import { CheckoutStatus, createCheckout } from './checkout';

export interface Poll {
    timestamp: string;
    captcha?: CaptchaResponse;
}

export interface ClientTicket {
    ticket: number;
    timestamp: string;
}

interface PollBody {
    token: string;
}

enum Status {
    Queue = 'queue',
    Checkout = 'checkout',
    Redirect = 'redirect',
}

interface PollResponse {
    status: Status;
    redirectUrl?: string;
}

interface PublicConfig {
    enabled: boolean;
    pollInterval: number;
    siteKey: string;
    messages: string[];
}

interface CaptchaResponse {
    success: boolean;
    score: number;
    action?: string;
    challenge_ts: string;
    hostname: string;
    'error-codes': string[];
}

export async function handleConfig(request: Request, url: URL, event: FetchEvent): Promise<Response> {
    // @ts-ignore: Actually valid, however not defined
    const cache: Cache = caches.default;

    let response = await cache.match(`${url.origin}/api/config`);
    if (!response) {
        response = await createConfig();
        event.waitUntil(cache.put(`${url.origin}/api/config`, response.clone()));
    }

    return response;
}

async function pullMessages(): Promise<string[]> {
    const messages = await QueueKV.get('messages');
    return JSON.parse(messages!);
}

async function createConfig(): Promise<Response> {
    const config = await pullConfig();
    let messages = await pullMessages();

    if (!messages) {
        messages = [];
    }

    if (messages.length === 0) {
        if (config.queue.saleComplete) {
            messages.push('THE SALE IS NOW COMPLETE, THANK YOU FOR PARTICIPATING');
        } else {
            if (config.queue.saleStart === -1 || config.queue.saleStart > currentTime()) {
                messages.push('THE SALE IS STARTING SOON');
            } else {
                messages.push('THE SALE HAS NOW STARTED');
            }
        }
    }

    const publicConfig: PublicConfig = {
        enabled: config.session.enabled,
        pollInterval: config.queue.pollInterval,
        siteKey: config.captcha.siteKey,
        messages,
    };

    return new Response(JSON.stringify(publicConfig), {
        headers: {
            'Cache-Control': 'max-age=15',
            'Content-Type': 'application/json',
        },
    });
}

async function verifyCaptcha(
    request: Request,
    config: Config,
    token: string,
    pollTime: Date,
): Promise<[boolean, Poll]> {
    const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: stringify({
            secret: config.captcha.secretKey,
            response: token,
            remoteip: request.headers.get(CLIENT_IP_HEADER),
        }),
    });

    switch (response.status) {
        case 200:
            const captcha: CaptchaResponse = await response.json();
            return [
                captcha.success && captcha.score >= 0.7 && captcha.action === config.captcha.action,
                { timestamp: pollTime.toISOString(), captcha },
            ];
    }

    return [false, { timestamp: new Date().toISOString() }];
}

function secureRandom() {
    const randomValues = crypto.getRandomValues(new Uint32Array(1));
    return randomValues[0] / Math.pow(2, 32);
}

function generateTicket(session: Session): number {
    return Math.round(secureRandom() * session.difficulty)
}

export async function handlePoll(request: Request, url: URL): Promise<Response> {
    const config = await pullConfig();

    if (!config.queue.enabled || request.headers.get('Content-Type') !== 'application/json') {
        return Forbidden();
    }

    const [sessionObj, session] = await pullSession(request, config);

    if (sessionObj.valid && session) {
        const pollTime = new Date();
        const currentTimestamp = currentTime();
        const lastPollTime = session.lastPollTime;
        if (session.checkout) {
            const [signedSessionCheckout, sessionExpiryCheckout] = await updateSession(request, config, session);
            if (session.checkout.status === CheckoutStatus.Created) {
                const response = await QueueResponse(request, config, session, Status.Checkout);
                setCookie(response, config.session.cookieName, signedSessionCheckout, sessionExpiryCheckout);
                return response;
            } else if (session.checkout.status === CheckoutStatus.AddressSubmitted) {
                const response = await QueueResponse(
                    request,
                    config,
                    session,
                    Status.Redirect,
                    session.checkout.invoice_url,
                );
                setCookie(response, config.session.cookieName, signedSessionCheckout, sessionExpiryCheckout);
                return response;
            }
        } else {
            session.lastPollTime = pollTime.getTime();

            const pollBody: PollBody = await request.json();
            const [validCaptcha, poll] = await verifyCaptcha(request, config, pollBody.token, pollTime);

            if (validCaptcha && pollTime.getTime() > lastPollTime + config.queue.pollInterval) {
                session.successfulPolls.push(poll);

                if (session.score > 0) {
                    if (config.queue.ticketGeneration && session.ticket === -1 && session.difficulty === -1) {
                        let difficulty = config.queue.difficulty / session.score;

                        if (session.failedPolls.length > 0) {
                            const ratio =
                                session.successfulPolls.length /
                                (session.successfulPolls.length + session.failedPolls.length);
                            difficulty = difficulty / ratio;
                        }

                        session.difficulty = difficulty;
                        session.ticket = generateTicket(session);
                    } else if (
                        config.queue.saleStart !== -1 &&
                        currentTimestamp > config.queue.saleStart &&
                        session.successfulPolls.length >= 10 &&
                        session.ticket !== -1 &&
                        session.difficulty !== -1 &&
                        !config.queue.saleComplete
                    ) {
                        const ticket = generateTicket(session);
                        session.clientTickets.push({ ticket, timestamp: new Date().toISOString() });

                        if (session.ticket === ticket) {
                            const signedCheckout = await createCheckout(request, config, session);
                            if (signedCheckout) {
                                const response = await QueueResponse(request, config, session, Status.Checkout);
                                setCookie(
                                    response,
                                    config.checkout.cookieName,
                                    signedCheckout,
                                    session.checkout!.expiry - currentTime(),
                                );
                                return response;
                            }
                        }
                    }
                }
            } else {
                session.failedPolls.push(poll);
                session.score -= 0.1;
            }
        }

        return QueueResponse(request, config, session, Status.Queue);
    }

    return Forbidden();
}

async function QueueResponse(
    request: Request,
    config: Config,
    session: Session,
    status: Status,
    redirectUrl?: string,
): Promise<Response> {
    const pollResponse: PollResponse = { status, redirectUrl };
    const [signedSession, sessionExpiry] = await updateSession(request, config, session);

    const response = new Response(JSON.stringify(pollResponse), {
        headers: {
            'Content-Type': 'application/json',
        },
    });

    setCookie(response, config.session.cookieName, signedSession, sessionExpiry);

    return response;
}