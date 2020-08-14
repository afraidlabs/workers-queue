import {
    Config,
    sleep,
    currentTime,
    CLIENT_IP_HEADER,
    USER_AGENT_HEADER,
    pullConfig,
    Forbidden,
    BadRequest,
} from './handler';
import { Session, HMAC_KEY, getCookie, pullSession, updateSession, setCookie } from './session';

const SignedCheckoutParams = ['exp', 'checkout', 'session', 'hmac'];

export enum CheckoutStatus {
    Created,
    AddressSubmitted,
}

interface Variant {
    id: number;
    inventory_quantity: number;
}

interface Product {
    product: {
        variants: Variant[];
    };
}

interface Customer {
    id: number;
}

interface Customers {
    customers: Customer[];
}

interface CustomerResponse {
    customer: Customer;
}

interface DraftOrder {
    draft_order: {
        id: number;
        invoice_url: string;
    };
}

export interface Checkout {
    id: number;
    expiry: number;
    status: CheckoutStatus;
    invoice_url?: string;
}

export interface ArchivedCheckout {
    email: string;
    clientIP: string;
    userAgent: string;
    checkout: Checkout;
}

interface Address {
    first_name?: string;
    last_name?: string;
    address1?: string;
    address2?: string;
    city?: string;
    phone?: string;
    zip?: string;
    province?: string;
    country?: string;
}

async function pullProductVariants(config: Config, retryLimit: number = 5): Promise<Variant[]> {
    const response = await fetch(
        `https://${SHOPIFY_HOST}/admin/api/2020-04/products/${config.checkout.productId}.json`,
        {
            method: 'GET',
            headers: {
                'X-Shopify-Access-Token': SHOPIFY_ACCESS_TOKEN,
            },
        },
    );

    switch (response.status) {
        case 200:
            const { product }: Product = await response.json();
            return product.variants;
        case 429:
            await sleep(1000);
        default:
            if (retryLimit > 0) {
                return pullProductVariants(config, (retryLimit -= -1));
            }
    }

    return [];
}

async function checkCustomer(config: Config, session: Session, retryLimit: number = 5): Promise<number | undefined> {
    const response = await fetch(
        `https://${SHOPIFY_HOST}/admin/api/2020-04/customers.json?email=${session.discord.email}`,
        {
            method: 'GET',
            headers: {
                'X-Shopify-Access-Token': SHOPIFY_ACCESS_TOKEN,
            },
        },
    );

    switch (response.status) {
        case 200:
            const { customers }: Customers = await response.json();
            if (customers.length === 1) {
                return customers[0].id;
            }
            return undefined;
        case 429:
            await sleep(1000);
        default:
            if (retryLimit > 0) {
                return checkCustomer(config, session, (retryLimit -= 1));
            }
    }
}

async function pullCustomer(
    config: Config,
    session: Session,
    retryLimit: number = 5,
    checkExistingCustomer: boolean = true,
): Promise<number | undefined> {
    if (checkExistingCustomer) {
        const existingCustomer = await checkCustomer(config, session);
        if (existingCustomer) {
            return existingCustomer;
        }
    }

    const response = await fetch(`https://${SHOPIFY_HOST}/admin/api/2020-04/customers.json`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Shopify-Access-Token': SHOPIFY_ACCESS_TOKEN,
        },
        body: JSON.stringify({
            customer: {
                email: session.discord.email,
            },
        }),
    });

    switch (response.status) {
        case 201:
            const { customer }: CustomerResponse = await response.json();
            return customer.id;
        case 429:
            await sleep(1000);
        default:
            if (retryLimit > 0) {
                return pullCustomer(config, session, (retryLimit -= 1), false);
            }
    }
}

export async function createCheckout(
    request: Request,
    config: Config,
    session: Session,
    retryLimit: number = 5,
): Promise<string | undefined> {
    const variants = await pullProductVariants(config);
    if (variants.length > 0 && variants[0].inventory_quantity > 0) {
        const customer = await pullCustomer(config, session);
        if (customer) {
            const response = await fetch(`https://${SHOPIFY_HOST}/admin/api/2020-04/draft_orders.json`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Shopify-Access-Token': SHOPIFY_ACCESS_TOKEN,
                },
                body: JSON.stringify({
                    draft_order: {
                        customer: {
                            id: customer,
                        },
                        line_items: [
                            {
                                variant_id: variants[0].id,
                                quantity: 1,
                            },
                        ],
                        note_attributes: [
                            {
                                name: 'Discord ID',
                                value: session.discord.id,
                            },
                            {
                                name: 'Session Identifier',
                                value: session.id,
                            },
                        ],
                    },
                }),
            });

            switch (response.status) {
                case 201:
                    const { draft_order }: DraftOrder = await response.json();
                    const checkout: Checkout = {
                        id: draft_order.id,
                        expiry: currentTime() + config.checkout.expiry,
                        status: CheckoutStatus.Created,
                        invoice_url: draft_order.invoice_url,
                    };

                    session.checkout = checkout;

                    const archive: ArchivedCheckout = {
                        email: session.discord.email,
                        clientIP: session.client.clientIP,
                        userAgent: session.client.userAgent,
                        checkout,
                    };

                    await CheckoutKV.put(session.discord.id, JSON.stringify(archive));

                    return signCheckout(request, session);
                case 429:
                    await sleep(2000);
                default:
                    if (retryLimit > 0) {
                        return createCheckout(request, config, session, (retryLimit -= 1));
                    }
            }
        }
    }

    return undefined;
}

async function signCheckout(request: Request, session: Session): Promise<string> {
    const encoder = new TextEncoder();

    const data = new Uint8Array([
        ...encoder.encode(`${session.checkout!.expiry}`),
        ...encoder.encode(`${session.checkout!.id}`),
        ...encoder.encode(session.id),
        ...encoder.encode(request.headers.get(CLIENT_IP_HEADER)!),
        ...encoder.encode(request.headers.get(USER_AGENT_HEADER)!),
    ]);

    const hmac = await crypto.subtle.sign('HMAC', await HMAC_KEY, data);

    const signedCheckout = new URLSearchParams();

    [`${session.checkout!.expiry}`, `${session.checkout!.id}`, session.id, Buffer.from(hmac).toString('hex')].forEach(
        (param, index) => {
            signedCheckout.set(SignedCheckoutParams[index], param);
        },
    );

    return signedCheckout.toString();
}

export async function verifyCheckout(request: Request, config: Config, session: Session): Promise<boolean> {
    const signedCheckout = getCookie(request, config.checkout.cookieName);
    const signedCheckoutParams = new URLSearchParams(signedCheckout);

    if (
        signedCheckout &&
        signedCheckout.length <= 256 &&
        SignedCheckoutParams.every((param) => signedCheckoutParams.has(param))
    ) {
        const encoder = new TextEncoder();
        const [exp, checkout, token, hmac]: string[] = SignedCheckoutParams.map(
            (param) => signedCheckoutParams.get(param)!,
        );

        const data = new Uint8Array([
            ...encoder.encode(exp),
            ...encoder.encode(checkout),
            ...encoder.encode(token),
            ...encoder.encode(request.headers.get(CLIENT_IP_HEADER)!),
            ...encoder.encode(request.headers.get(USER_AGENT_HEADER)!),
        ]);

        const valid = await crypto.subtle.verify('HMAC', await HMAC_KEY, Buffer.from(hmac, 'hex'), data);
        const expiry = parseInt(exp, 10);

        return (
            valid && expiry > currentTime() && session.id === token && session.checkout!.id === parseInt(checkout, 10)
        );
    }

    return false;
}

export async function handleAddress(request: Request): Promise<Response> {
    const config = await pullConfig();
    const [sessionObj, session] = await pullSession(request, config);
    if (sessionObj.valid && session && (await verifyCheckout(request, config, session))) {
        const {
            first_name,
            last_name,
            address1,
            address2,
            city,
            phone,
            zip,
            province,
            country,
        }: Address = await request.json();

        const shopifyResponse = await fetch(
            `https://${SHOPIFY_HOST}/admin/api/2020-04/draft_orders/${session.checkout!.id}.json`,
            {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Shopify-Access-Token': SHOPIFY_ACCESS_TOKEN,
                },
                body: JSON.stringify({
                    draft_order: {
                        shipping_address: {
                            first_name,
                            last_name,
                            address1,
                            address2,
                            city,
                            phone,
                            zip,
                            province,
                            country,
                        },
                    },
                }),
            },
        );

        switch (shopifyResponse.status) {
            case 200 || 202:
                session.checkout!.status = CheckoutStatus.AddressSubmitted;
                const { draft_order }: DraftOrder = await shopifyResponse.json();
                const response = new Response(
                    JSON.stringify({
                        status: 'redirect',
                        redirectUrl: session.checkout!.invoice_url,
                    }),
                );
                const [signedSession, sessionExpiry] = await updateSession(request, config, session);
                setCookie(response, config.session.cookieName, signedSession, sessionExpiry);
                return response;
            default:
                return BadRequest();
        }
    }

    return Forbidden();
}
