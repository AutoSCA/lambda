import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
    DynamoDBDocumentClient,
    GetCommand,
    PutCommand,
    UpdateCommand,
    DeleteCommand,
    ScanCommand
} from '@aws-sdk/lib-dynamodb';
import crypto from 'crypto';
import util from 'util';

const scryptAsync = util.promisify(crypto.scrypt);

const client = new DynamoDBClient({
    region: process.env.AWS_REGION || 'ap-northeast-2'
});
const docClient = DynamoDBDocumentClient.from(client);

const USER_TABLE = process.env.DYNAMO_DB_TABLE_USER || 'gachon-p-project-sca-user';
const SESSION_TABLE = process.env.DYNAMO_DB_TABLE_SESSION || 'gachon-p-project-sca-session';
const OTP_TABLE = process.env.DYNAMO_DB_TABLE_EMAIL_OTP || 'gachon-p-project-sca-email-otp';
const SESSION_COOKIE_NAME = process.env.SESSION_COOKIE_NAME || 'autosca_session';
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN !== undefined ? process.env.COOKIE_DOMAIN : '.autosca.cloud';
const COOKIE_SAME_SITE = process.env.COOKIE_SAME_SITE || 'Lax';
const SESSION_TTL_SEC = Number(process.env.SESSION_TTL_SEC) || 60 * 60 * 24 * 7; // 7일
const DYNAMO_TTL_BUFFER_SEC = 3600;

const SESSION_TOKEN_PATTERN = /^[a-f0-9]{64}$/;
const MIN_PASSWORD_LEN = 8;
const MAX_PASSWORD_LEN = 128;
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

function isValidPassword(pw) {
    if (typeof pw !== 'string') return false;
    if (pw.length < MIN_PASSWORD_LEN || pw.length > MAX_PASSWORD_LEN) return false;
    return (
        /[A-Z]/.test(pw) &&
        /[a-z]/.test(pw) &&
        /[0-9]/.test(pw) &&
        /[^A-Za-z0-9\s]/.test(pw)
    );
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

async function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const derived = await scryptAsync(password, salt, 64);
    return `scrypt$${salt}$${Buffer.from(derived).toString('hex')}`;
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

async function resolveSession(event) {
    const rawToken = extractCookie(event, SESSION_COOKIE_NAME);
    if (!rawToken) {
        return { hasCookie: false, session: null };
    }
    if (!SESSION_TOKEN_PATTERN.test(rawToken)) {
        return { hasCookie: true, session: null };
    }

    const sessionId = sha256Hex(rawToken);
    const res = await docClient.send(new GetCommand({
        TableName: SESSION_TABLE,
        Key: { session_id: sessionId }
    }));

    const session = res.Item;
    const nowSec = Math.floor(Date.now() / 1000);
    if (!session || !session.user_uuid || !session.email || nowSec > Number(session.expires_at ?? 0)) {
        if (session) {
            await docClient.send(new DeleteCommand({
                TableName: SESSION_TABLE,
                Key: { session_id: sessionId }
            })).catch(() => { });
        }
        return { hasCookie: true, session: null };
    }
    return { hasCookie: true, session };
}

async function invalidateOtherUserSessions(email, userUuid, keepSessionId) {
    const sessionIds = [];
    let exclusiveStartKey;

    do {
        const filterExpr = userUuid ? 'email = :email OR user_uuid = :userUuid' : 'email = :email';
        const exprValues = userUuid
            ? { ':email': email, ':userUuid': userUuid }
            : { ':email': email };

        const scanRes = await docClient.send(new ScanCommand({
            TableName: SESSION_TABLE,
            FilterExpression: filterExpr,
            ExpressionAttributeValues: exprValues,
            ProjectionExpression: 'session_id',
            ...(exclusiveStartKey ? { ExclusiveStartKey: exclusiveStartKey } : {})
        }));

        for (const item of scanRes.Items ?? []) {
            if (item?.session_id && item.session_id !== keepSessionId) {
                sessionIds.push(item.session_id);
            }
        }
        exclusiveStartKey = scanRes.LastEvaluatedKey;
    } while (exclusiveStartKey);

    if (sessionIds.length === 0) return;

    await Promise.allSettled(
        sessionIds.map((sessionId) =>
            docClient.send(new DeleteCommand({
                TableName: SESSION_TABLE,
                Key: { session_id: sessionId }
            }))
        )
    );
}

export const handler = async (event) => {
    // CORS Preflight(OPTIONS) 요청 처리
    if (event.requestContext?.http?.method === 'OPTIONS' || event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers: buildHeaders(event), body: '' };
    }

    try {
        // 1. Cookie 세션 토큰 검증
        const { hasCookie, session } = await resolveSession(event);
        if (!session) {
            return respond(
                event,
                401,
                {
                    result: false,
                    code: 'UNAUTHORIZED',
                    data: hasCookie
                        ? '세션이 만료되었습니다. 다시 로그인해주세요.'
                        : '로그인이 필요합니다.'
                },
                hasCookie ? { 'Set-Cookie': buildClearSessionCookie() } : {}
            );
        }

        const sessionEmail = String(session.email).trim().toLowerCase();
        const sessionUserUuid = String(session.user_uuid).trim();

        // 2. 요청 Body 파싱 및 기본 입력 검증
        let body;
        try {
            body = typeof event.body === 'string'
                ? JSON.parse(event.body || '{}')
                : (event.body ?? event ?? {});
        }
        catch {
            return respond(event, 400, {
                result: false,
                code: 'INVALID_JSON',
                data: '요청 JSON 형식이 올바르지 않습니다.'
            });
        }

        const currentPassword = typeof body.current_password === 'string' ? body.current_password : '';
        const newPassword = typeof body.new_password === 'string' ? body.new_password : '';

        if (!currentPassword) {
            return respond(event, 400, {
                result: false,
                code: 'CURRENT_PASSWORD_REQUIRED',
                data: '현재 비밀번호를 입력해주세요.'
            });
        }
        if (!isValidPassword(newPassword)) {
            return respond(event, 400, {
                result: false,
                code: 'WEAK_PASSWORD',
                data: '8자 이상, 영문 대소문자·숫자·특수기호를 모두 포함해주세요.'
            });
        }
        if (newPassword === currentPassword) {
            return respond(event, 400, {
                result: false,
                code: 'SAME_PASSWORD',
                data: '현재 비밀번호와 다른 새 비밀번호를 입력해주세요.'
            });
        }
        if (currentPassword.length > MAX_PASSWORD_LEN) {
            return respond(event, 403, {
                result: false,
                code: 'INVALID_PASSWORD',
                data: '현재 비밀번호가 올바르지 않습니다.'
            });
        }

        // 3. 회원 조회 및 현재 비밀번호 검증
        const userResponse = await docClient.send(new GetCommand({
            TableName: USER_TABLE,
            Key: { email: sessionEmail }
        }));

        const user = userResponse.Item;
        if (!user || String(user.user_uuid || '').trim() !== sessionUserUuid) {
            return respond(
                event,
                401,
                {
                    result: false,
                    code: 'UNAUTHORIZED',
                    data: '세션이 만료되었습니다. 다시 로그인해주세요.'
                },
                { 'Set-Cookie': buildClearSessionCookie() }
            );
        }

        const isPasswordValid = await verifyPassword(currentPassword, user.password_hash);
        if (!isPasswordValid) {
            return respond(event, 403, {
                result: false,
                code: 'INVALID_PASSWORD',
                data: '현재 비밀번호가 올바르지 않습니다.'
            });
        }

        // 4. 새 비밀번호 단방향 해시 생성 및 원자적 업데이트
        const newPasswordHash = await hashPassword(newPassword);
        try {
            await docClient.send(new UpdateCommand({
                TableName: USER_TABLE,
                Key: { email: sessionEmail },
                UpdateExpression: 'SET password_hash = :passwordHash',
                ConditionExpression: 'attribute_exists(email) AND user_uuid = :userUuid',
                ExpressionAttributeValues: {
                    ':passwordHash': newPasswordHash,
                    ':userUuid': sessionUserUuid
                }
            }));
        }
        catch (updateError) {
            if (updateError?.name === 'ConditionalCheckFailedException') {
                return respond(
                    event,
                    401,
                    {
                        result: false,
                        code: 'UNAUTHORIZED',
                        data: '세션이 만료되었습니다. 다시 로그인해주세요.'
                    },
                    { 'Set-Cookie': buildClearSessionCookie() }
                );
            }
            throw updateError;
        }

        // 5. 현재 브라우저 세션 토큰 회전(신규 발급) 및 기존/타 기기 세션·재설정 OTP 전부 폐기
        const newRawToken = crypto.randomBytes(32).toString('hex');
        const newSessionId = sha256Hex(newRawToken);
        const nowSec = Math.floor(Date.now() / 1000);
        const expiresAt = nowSec + SESSION_TTL_SEC;
        const role = Number(user.role ?? session.role ?? 0);

        await docClient.send(new PutCommand({
            TableName: SESSION_TABLE,
            Item: {
                session_id: newSessionId,
                user_uuid: sessionUserUuid,
                email: sessionEmail,
                role,
                expires_at: expiresAt,
                ttl: expiresAt + DYNAMO_TTL_BUFFER_SEC
            }
        }));

        await Promise.allSettled([
            invalidateOtherUserSessions(sessionEmail, sessionUserUuid, newSessionId),
            docClient.send(new DeleteCommand({
                TableName: OTP_TABLE,
                Key: { email: `reset#${sessionEmail}` }
            }))
        ]);

        return respond(
            event,
            200,
            {
                result: true,
                email: sessionEmail
            },
            {
                'Set-Cookie': buildSessionCookie(newRawToken, SESSION_TTL_SEC)
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