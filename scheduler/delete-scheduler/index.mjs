import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, DeleteCommand } from '@aws-sdk/lib-dynamodb';
import crypto from 'crypto';

const region = process.env.AWS_REGION || 'ap-northeast-2';
const dynamoClient = new DynamoDBClient({ region });
const docClient = DynamoDBDocumentClient.from(dynamoClient);

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
        'Access-Control-Allow-Methods': 'DELETE, OPTIONS',
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
        // 1. Cookie 헤더의 세션 토큰 검증
        const session = await resolveSession(event);
        if (!session) {
            return respond(event, 401, {
                result: false,
                data: '로그인이 필요합니다.'
            });
        }

        const ownerUuid = String(session.user_uuid).trim();

        // 2. 쿼리 스트링(?scheduler_uuid=...)에서 scheduler_uuid 추출
        const schedulerUuid = String(
            event.queryStringParameters?.scheduler_uuid ??
            event.queryStringParameters?.['scheduler-uuid'] ??
            event.scheduler_uuid ??
            event['scheduler-uuid'] ??
            ''
        ).trim();

        if (!schedulerUuid) {
            return respond(event, 400, {
                result: false,
                data: 'scheduler_uuid 쿼리 스트링은 필수 값입니다.'
            });
        }

        // 3. DynamoDB 에서 해당 scheduler_uuid 존재 및 소유권 조회
        const dynamoResponse = await docClient.send(new GetCommand({
            TableName: TABLE_NAME,
            Key: {
                scheduler_uuid: schedulerUuid
            }
        }));

        if (!dynamoResponse.Item) {
            return respond(event, 404, {
                result: false,
                data: `해당 scheduler_uuid(${schedulerUuid}) 정보를 찾을 수 없습니다.`
            });
        }

        if (String(dynamoResponse.Item.user_uuid || '').trim() !== ownerUuid) {
            return respond(event, 403, {
                result: false,
                data: '해당 예약 항목을 삭제할 권한이 없습니다.'
            });
        }

        // 4. 소유자 조건을 걸고 삭제
        await docClient.send(new DeleteCommand({
            TableName: TABLE_NAME,
            Key: {
                scheduler_uuid: schedulerUuid
            },
            ConditionExpression: 'user_uuid = :ownerUuid',
            ExpressionAttributeValues: {
                ':ownerUuid': ownerUuid
            }
        }));

        return respond(event, 200, {
            result: true,
            scheduler_uuid: schedulerUuid
        });
    }
    catch (error) {
        if (error?.name === 'ConditionalCheckFailedException') {
            return respond(event, 403, {
                result: false,
                data: '해당 예약 항목을 삭제할 권한이 없습니다.'
            });
        }
        return respond(event, 500, {
            result: false,
            data: error.message
        });
    }
};