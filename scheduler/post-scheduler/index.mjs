import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
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

        // 2. 요청 Body 파싱 및 입력 검증
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
        const rawDay = body.scheduler_day;
        const rawTime = body.scheduler_time;

        if (
            !githubUrl ||
            rawDay === undefined || rawDay === null || String(rawDay).trim() === '' ||
            rawTime === undefined || rawTime === null || String(rawTime).trim() === ''
        ) {
            return respond(event, 400, {
                result: false,
                data: 'github_url, scheduler_day, scheduler_time 은 필수 값입니다.'
            });
        }

        const schedulerDay = Number(rawDay);
        const schedulerTime = Number(rawTime);

        // 요일 검증: 월요일(0) ~ 일요일(6)
        if (!Number.isInteger(schedulerDay) || schedulerDay < 0 || schedulerDay > 6) {
            return respond(event, 400, {
                result: false,
                data: 'scheduler_day 는 0(월요일)부터 6(일요일) 사이의 정수만 설정할 수 있습니다.'
            });
        }

        // 시간 검증: 1시(1) ~ 24시(24)
        if (!Number.isInteger(schedulerTime) || schedulerTime < 1 || schedulerTime > 24) {
            return respond(event, 400, {
                result: false,
                data: 'scheduler_time 은 1(1시)부터 24(24시) 사이의 정수만 설정할 수 있습니다.'
            });
        }

        // 3. 고유한 scheduler_uuid 생성 및 세션 소유자의 user_uuid 로 저장
        const newItem = {
            scheduler_uuid: crypto.randomUUID(),
            user_uuid: String(session.user_uuid).trim(),
            github_url: githubUrl,
            scheduler_day: schedulerDay,
            scheduler_time: schedulerTime,
            scheduler_status: 1
        };

        await docClient.send(new PutCommand({
            TableName: TABLE_NAME,
            Item: newItem,
            ConditionExpression: 'attribute_not_exists(scheduler_uuid)'
        }));

        return respond(event, 201, {
            result: true,
            scheduler_uuid: newItem.scheduler_uuid
        });
    }
    catch (error) {
        return respond(event, 500, {
            result: false,
            data: error.message
        });
    }
};
