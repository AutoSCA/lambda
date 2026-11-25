import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, ScanCommand } from '@aws-sdk/lib-dynamodb';
import crypto from 'crypto';

const client = new DynamoDBClient({
    region: process.env.AWS_REGION || 'ap-northeast-2'
});
const docClient = DynamoDBDocumentClient.from(client);

const TABLE_NAME = process.env.DYNAMO_DB_TABLE_SANDBOX || 'gachon-p-project-sca-sandbox';
const SESSION_TABLE = process.env.DYNAMO_DB_TABLE_SESSION || 'gachon-p-project-sca-session';
const SESSION_COOKIE_NAME = process.env.SESSION_COOKIE_NAME || 'autosca_session';
const SESSION_TOKEN_PATTERN = /^[a-f0-9]{64}$/;

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
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
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

function isRunningStatus(status) {
    const n = Number(status);
    return !Number.isNaN(n) && n >= 0 && n < 7;
}

export const handler = async (event) => {
    // CORS Preflight(OPTIONS) 요청 처리
    if (event.requestContext?.http?.method === 'OPTIONS' || event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers: buildHeaders(event), body: '' };
    }

    try {
        // 1. 헤더 세션 쿠키 우선 확인 -> 세션이 없을 때만 쿼리 스트링의 user_uuid 확인
        const { hasCookie, session } = await resolveSession(event);
        let userUuid = '';

        if (session) {
            userUuid = String(session.user_uuid).trim();
        } else {
            const queryUserUuid = String(
                event.queryStringParameters?.user_uuid ?? event.user_uuid ?? ''
            ).trim();
            if (queryUserUuid) {
                userUuid = queryUserUuid;
            } else if (hasCookie) {
                return respond(event, 401, {
                    result: false,
                    data: '세션이 만료되었습니다. 다시 로그인해주세요.'
                });
            } else {
                return respond(event, 400, {
                    result: false,
                    data: 'user_uuid 쿼리 스트링은 필수 값입니다.'
                });
            }
        }

        // 2. 해당 사용자의 동작 중(0 <= sandbox_status < 7) 샌드박스 상태만 일괄 조회 (만료된 게스트 행 제외)
        const runningItems = [];
        const nowSec = Math.floor(Date.now() / 1000);
        let lastEvaluatedKey;

        do {
            const response = await docClient.send(new ScanCommand({
                TableName: TABLE_NAME,
                FilterExpression: 'user_uuid = :userUuid',
                ProjectionExpression: 'sandbox_uuid, sandbox_status, created_at, #ttl',
                ExpressionAttributeNames: {
                    '#ttl': 'ttl'
                },
                ExpressionAttributeValues: {
                    ':userUuid': userUuid
                },
                ExclusiveStartKey: lastEvaluatedKey
            }));

            if (Array.isArray(response.Items)) {
                for (const item of response.Items) {
                    if (item.ttl !== undefined && nowSec > Number(item.ttl)) {
                        continue;
                    }
                    if (item.sandbox_uuid && isRunningStatus(item.sandbox_status)) {
                        runningItems.push({
                            sandbox_uuid: item.sandbox_uuid,
                            sandbox_status: item.sandbox_status,
                            created_at: item.created_at ?? null
                        });
                    }
                }
            }
            lastEvaluatedKey = response.LastEvaluatedKey;
        } while (lastEvaluatedKey);

        return respond(event, 200, {
            result: true,
            data: runningItems
        });
    }
    catch (error) {
        return respond(event, 500, {
            result: false,
            data: error.message
        });
    }
};