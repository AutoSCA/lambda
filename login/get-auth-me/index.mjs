import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, DeleteCommand } from '@aws-sdk/lib-dynamodb';
import crypto from 'crypto';

const client = new DynamoDBClient({
    region: process.env.AWS_REGION || 'ap-northeast-2'
});
const docClient = DynamoDBDocumentClient.from(client);

const SESSION_TABLE = process.env.DYNAMO_DB_TABLE_SESSION || 'gachon-p-project-sca-session';
const SESSION_COOKIE_NAME = process.env.SESSION_COOKIE_NAME || 'autosca_session';
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN !== undefined ? process.env.COOKIE_DOMAIN : '.autosca.cloud';
const COOKIE_SAME_SITE = process.env.COOKIE_SAME_SITE || 'Lax';

const SESSION_TOKEN_PATTERN = /^[a-f0-9]{64}$/;

const ALLOWED_ORIGINS = new Set(
    (process.env.ALLOWED_ORIGINS || 'https://autosca.cloud,https://www.autosca.cloud,http://localhost:5173,http://127.0.0.1:5173')
        .split(',')
        .map((v) => v.trim())
        .filter(Boolean)
);

function buildHeaders(event, extraHeaders = {}) {
    const reqOrigin = event?.headers?.origin || event?.headers?.Origin || '';
    const allowOrigin = ALLOWED_ORIGINS.has(reqOrigin) ? reqOrigin : 'https://autosca.cloud';

    return {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        'Access-Control-Allow-Origin': allowOrigin,
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        Vary: 'Origin',
        ...extraHeaders
    };
}

function respond(event, statusCode, payload, extraHeaders = {}) {
    return {
        statusCode,
        headers: buildHeaders(event, extraHeaders),
        body: JSON.stringify(payload)
    };
}

function sha256Hex(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
}

function extractCookie(event, name) {
    const pairs = [];
    if (Array.isArray(event?.cookies)) {
        pairs.push(...event.cookies);
    }
    const headerCookie = event?.headers?.cookie || event?.headers?.Cookie;
    if (typeof headerCookie === 'string' && headerCookie.trim()) {
        pairs.push(...headerCookie.split(';'));
    }
    for (const raw of pairs) {
        const idx = raw.indexOf('=');
        if (idx === -1) continue;
        const key = raw.slice(0, idx).trim();
        if (key === name) {
            return raw.slice(idx + 1).trim();
        }
    }
    return '';
}

function buildClearSessionCookie() {
    const attrs = [
        `${SESSION_COOKIE_NAME}=`,
        'Path=/',
        'HttpOnly',
        'Secure',
        `SameSite=${COOKIE_SAME_SITE}`,
        'Max-Age=0',
        'Expires=Thu, 01 Jan 1970 00:00:00 GMT'
    ];
    if (COOKIE_DOMAIN) {
        attrs.push(`Domain=${COOKIE_DOMAIN}`);
    }
    return attrs.join('; ');
}

export const handler = async (event) => {
    // CORS Preflight(OPTIONS) 요청 처리
    if (event.requestContext?.http?.method === 'OPTIONS' || event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers: buildHeaders(event), body: '' };
    }

    try {
        // 1. 요청 쿠키에서 세션 토큰 추출
        const rawToken = extractCookie(event, SESSION_COOKIE_NAME);
        if (!rawToken) {
            return respond(event, 200, {
                result: true,
                authenticated: false
            });
        }

        if (!SESSION_TOKEN_PATTERN.test(rawToken)) {
            return respond(
                event,
                200,
                { result: true, authenticated: false },
                { 'Set-Cookie': buildClearSessionCookie() }
            );
        }

        // 2. 세션 테이블에서 해시된 session_id 조회
        const sessionId = sha256Hex(rawToken);
        const sessionResponse = await docClient.send(new GetCommand({
            TableName: SESSION_TABLE,
            Key: { session_id: sessionId }
        }));

        const session = sessionResponse.Item;
        const nowSec = Math.floor(Date.now() / 1000);

        if (!session || nowSec > Number(session.expires_at ?? 0)) {
            if (session) {
                await docClient.send(new DeleteCommand({
                    TableName: SESSION_TABLE,
                    Key: { session_id: sessionId }
                })).catch(() => {});
            }

            return respond(
                event,
                200,
                { result: true, authenticated: false },
                { 'Set-Cookie': buildClearSessionCookie() }
            );
        }

        // 3. 인증된 최소 프로필만 반환 (user_uuid 미노출)
        return respond(event, 200, {
            result: true,
            authenticated: true,
            email: session.email,
            role: Number(session.role ?? 0)
        });
    }
    catch (error) {
        return respond(event, 500, {
            result: false,
            data: error.message
        });
    }
};
