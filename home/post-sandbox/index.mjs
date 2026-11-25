import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import crypto from 'crypto';

const client = new DynamoDBClient({
    region: process.env.AWS_REGION || 'ap-northeast-2'
});
const docClient = DynamoDBDocumentClient.from(client);

const TABLE_NAME = process.env.DYNAMO_DB_TABLE_SANDBOX || 'gachon-p-project-sca-sandbox';
const SESSION_TABLE = process.env.DYNAMO_DB_TABLE_SESSION || 'gachon-p-project-sca-session';
const SESSION_COOKIE_NAME = process.env.SESSION_COOKIE_NAME || 'autosca_session';
const SESSION_TOKEN_PATTERN = /^[a-f0-9]{64}$/;
const GUEST_SANDBOX_TTL_SEC = Number(process.env.GUEST_SANDBOX_TTL_SEC) || 60 * 60 * 24; // 비로그인 24시간 자동 만료

const ALLOWED_ORIGINS = new Set(
    (process.env.ALLOWED_ORIGINS || 'https://autosca.cloud,https://www.autosca.cloud,http://localhost:5173,http://127.0.0.1:5173')
        .split(',')
        .map((v) => v.trim())
        .filter(Boolean)
);

function buildHeaders(event) {
    const reqOrigin = event?.headers?.origin || event?.headers?.Origin || '';
    const allowOrigin = ALLOWED_ORIGINS.has(reqOrigin) ? reqOrigin : 'https://autosca.cloud';

    return {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        'Access-Control-Allow-Origin': allowOrigin,
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        Vary: 'Origin'
    };
}

function respond(event, statusCode, payload) {
    return {
        statusCode,
        headers: buildHeaders(event),
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
    if (!session || !session.user_uuid || nowSec > Number(session.expires_at ?? 0)) {
        return { hasCookie: true, session: null };
    }
    return { hasCookie: true, session };
}

export const handler = async (event) => {
    // CORS Preflight(OPTIONS) 요청 처리
    if (event.requestContext?.http?.method === 'OPTIONS' || event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers: buildHeaders(event), body: '' };
    }

    try {
        // 1. API Gateway Body(JSON) 또는 Lambda 콘솔 직접 테스트 입력 파싱
        let body;
        try {
            body = typeof event.body === 'string'
                ? JSON.parse(event.body || '{}')
                : (event.body ?? event ?? {});
        }
        catch {
            return respond(event, 400, {
                result: false,
                data: '요청 JSON 형식이 올바르지 않습니다.'
            });
        }

        const githubUrl = body.github_url !== undefined ? String(body.github_url).trim() : '';
        if (!githubUrl) {
            return respond(event, 400, {
                result: false,
                data: 'github_url 은 필수 값입니다.'
            });
        }

        // 2. 헤더 세션 쿠키 우선 확인 -> 세션이 없을 때만 바디의 user_uuid 확인
        const { hasCookie, session } = await resolveSession(event);
        const isGuest = !session;
        let userUuid = '';

        if (session) {
            userUuid = String(session.user_uuid).trim();
        } else {
            const bodyUserUuid = body.user_uuid !== undefined ? String(body.user_uuid).trim() : '';
            if (bodyUserUuid) {
                userUuid = bodyUserUuid;
            } else if (hasCookie) {
                return respond(event, 401, {
                    result: false,
                    data: '세션이 만료되었습니다. 다시 로그인해주세요.'
                });
            } else {
                return respond(event, 400, {
                    result: false,
                    data: 'user_uuid 와 github_url 은 필수 값입니다.'
                });
            }
        }

        // 3. 고유한 sandbox_uuid 생성, 초기 상태(0) 및 등록 일시(Unix Epoch 초 단위) 설정
        // 비로그인(게스트) 요청에만 DynamoDB TTL(기본 24시간)을 부여하고, 로그인 회원은 영구 보관
        const nowSec = Math.floor(Date.now() / 1000);
        const newItem = {
            sandbox_uuid: crypto.randomUUID(),
            user_uuid: userUuid,
            github_url: githubUrl,
            sandbox_status: '0',
            created_at: nowSec
        };
        if (isGuest) {
            newItem.ttl = nowSec + GUEST_SANDBOX_TTL_SEC;
        }

        // 4. DynamoDB 에 행 추가 (중복 sandbox_uuid 덮어쓰기 방지 포함)
        await docClient.send(new PutCommand({
            TableName: TABLE_NAME,
            Item: newItem,
            ConditionExpression: 'attribute_not_exists(sandbox_uuid)'
        }));

        return respond(event, 201, {
            result: true,
            sandbox_uuid: newItem.sandbox_uuid,
            created_at: newItem.created_at
        });
    }
    catch (error) {
        return respond(event, 500, {
            result: false,
            data: error.message
        });
    }
};