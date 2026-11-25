import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, ScanCommand } from '@aws-sdk/lib-dynamodb';
import crypto from 'crypto';

const client = new DynamoDBClient({
    region: process.env.AWS_REGION || 'ap-northeast-2'
});
const docClient = DynamoDBDocumentClient.from(client);

const TABLE_NAME = process.env.DYNAMO_DB_TABLE_SCHEDULER || 'gachon-p-project-sca-scheduler';
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
    if (!SESSION_TOKEN_PATTERN.test(rawToken)) {
        return null;
    }

    const sessionId = sha256Hex(rawToken);
    const res = await docClient.send(new GetCommand({
        TableName: SESSION_TABLE,
        Key: { session_id: sessionId }
    }));

    const session = res.Item;
    const nowSec = Math.floor(Date.now() / 1000);
    if (!session || !session.user_uuid || nowSec > Number(session.expires_at ?? 0)) {
        return null;
    }
    return session;
}

export const handler = async (event) => {
    // CORS Preflight(OPTIONS) 요청 처리
    if (event.requestContext?.http?.method === 'OPTIONS' || event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers: buildHeaders(event), body: '' };
    }

    try {
        // 1. Cookie 헤더의 세션 토큰 검증 후 서버에서 user_uuid 조회
        const session = await resolveSession(event);
        if (!session) {
            return respond(event, 401, {
                result: false,
                data: '로그인이 필요합니다.'
            });
        }

        const userUuid = String(session.user_uuid).trim();

        // 2. DynamoDB 에서 해당 세션 소유자의 스케줄러 항목 전체 조회 (페이지네이션 대응)
        const items = [];
        let lastEvaluatedKey;

        do {
            const response = await docClient.send(new ScanCommand({
                TableName: TABLE_NAME,
                FilterExpression: 'user_uuid = :userUuid',
                ExpressionAttributeValues: {
                    ':userUuid': userUuid
                },
                ExclusiveStartKey: lastEvaluatedKey
            }));

            if (Array.isArray(response.Items)) {
                for (const item of response.Items) {
                    const { user_uuid: _hidden, ...publicItem } = item;
                    items.push(publicItem);
                }
            }
            lastEvaluatedKey = response.LastEvaluatedKey;
        } while (lastEvaluatedKey);

        return respond(event, 200, {
            result: true,
            data: items
        });
    }
    catch (error) {
        return respond(event, 500, {
            result: false,
            data: error.message
        });
    }
};
