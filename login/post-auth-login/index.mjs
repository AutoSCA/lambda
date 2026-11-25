import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import crypto from 'crypto';
import util from 'util';

const scryptAsync = util.promisify(crypto.scrypt);

const client = new DynamoDBClient({
    region: process.env.AWS_REGION || 'ap-northeast-2'
});
const docClient = DynamoDBDocumentClient.from(client);

const USER_TABLE = process.env.DYNAMO_DB_TABLE_USER || 'gachon-p-project-sca-user';
const SESSION_TABLE = process.env.DYNAMO_DB_TABLE_SESSION || 'gachon-p-project-sca-session';
const SESSION_COOKIE_NAME = process.env.SESSION_COOKIE_NAME || 'autosca_session';
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN !== undefined ? process.env.COOKIE_DOMAIN : '.autosca.cloud';
const COOKIE_SAME_SITE = process.env.COOKIE_SAME_SITE || 'Lax';
const SESSION_TTL_SEC = Number(process.env.SESSION_TTL_SEC) || 60 * 60 * 24 * 7; // 7일
const DYNAMO_TTL_BUFFER_SEC = 3600;

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const DUMMY_SALT = '00000000000000000000000000000000';
const DUMMY_DERIVED_HEX = '0'.repeat(128);

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
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
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

function safeHexEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) {
        return false;
    }
    const bufA = Buffer.from(a, 'hex');
    const bufB = Buffer.from(b, 'hex');
    if (bufA.length === 0 || bufA.length !== bufB.length) {
        return false;
    }
    return crypto.timingSafeEqual(bufA, bufB);
}

async function verifyPassword(password, storedHash) {
    const parts = typeof storedHash === 'string' ? storedHash.split('$') : [];
    const validFormat =
        parts.length === 3 &&
        parts[0] === 'scrypt' &&
        parts[1].length > 0 &&
        parts[2].length === 128;

    const salt = validFormat ? parts[1] : DUMMY_SALT;
    const targetHex = validFormat ? parts[2] : DUMMY_DERIVED_HEX;

    const derived = await scryptAsync(password, salt, 64);
    const derivedHex = Buffer.from(derived).toString('hex');
    const matched = safeHexEqual(derivedHex, targetHex);

    return validFormat && matched;
}

function buildSessionCookie(rawToken, maxAgeSec) {
    const attrs = [
        `${SESSION_COOKIE_NAME}=${rawToken}`,
        'Path=/',
        'HttpOnly',
        'Secure',
        `SameSite=${COOKIE_SAME_SITE}`,
        `Max-Age=${maxAgeSec}`
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
        // 1. 요청 Body 파싱 및 기본 입력 검증
        let body;
        try {
            body = typeof event.body === 'string'
                ? JSON.parse(event.body || '{}')
                : (event.body ?? event ?? {});
        }
        catch {
            return respond(event, 400, { result: false, data: '요청 JSON 형식이 올바르지 않습니다.' });
        }

        const email = body.email !== undefined ? String(body.email).trim().toLowerCase() : '';
        const password = typeof body.password === 'string' ? body.password : '';

        if (!email || !EMAIL_PATTERN.test(email)) {
            return respond(event, 400, { result: false, data: '올바른 이메일 형식을 입력해주세요.' });
        }
        if (!password) {
            return respond(event, 400, { result: false, data: '비밀번호를 입력해주세요.' });
        }

        // 2. 회원 조회 및 비밀번호 검증 (미가입 계정도 동일한 scrypt 연산 수행해 타이밍·열거 방어)
        const userResponse = await docClient.send(new GetCommand({
            TableName: USER_TABLE,
            Key: { email }
        }));

        const user = userResponse.Item;
        const isPasswordValid = await verifyPassword(password, user?.password_hash);

        if (!user || !isPasswordValid) {
            return respond(event, 401, {
                result: false,
                data: '이메일 또는 비밀번호가 올바르지 않습니다.'
            });
        }

        // 3. 세션 토큰 발급 (쿠키에는 원문 랜덤 토큰만, DB에는 SHA-256 해시만 저장)
        const rawToken = crypto.randomBytes(32).toString('hex');
        const sessionId = sha256Hex(rawToken);
        const nowSec = Math.floor(Date.now() / 1000);
        const expiresAt = nowSec + SESSION_TTL_SEC;
        const role = Number(user.role ?? 0);

        await docClient.send(new PutCommand({
            TableName: SESSION_TABLE,
            Item: {
                session_id: sessionId,
                user_uuid: user.user_uuid,
                email: user.email,
                role,
                expires_at: expiresAt,
                ttl: expiresAt + DYNAMO_TTL_BUFFER_SEC
            }
        }));

        // 4. HttpOnly 세션 쿠키 설정 (응답 바디에 user_uuid 미노출)
        return respond(
            event,
            200,
            {
                result: true,
                email: user.email,
                role
            },
            {
                'Set-Cookie': buildSessionCookie(rawToken, SESSION_TTL_SEC)
            }
        );
    }
    catch (error) {
        return respond(event, 500, {
            result: false,
            data: error.message
        });
    }
};
