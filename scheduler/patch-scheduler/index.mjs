import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
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
        'Access-Control-Allow-Methods': 'PATCH, OPTIONS',
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

        // 2. 요청 Body 파싱
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

        const schedulerUuid = body.scheduler_uuid !== undefined ? String(body.scheduler_uuid).trim() : '';

        if (!schedulerUuid) {
            return respond(event, 400, {
                result: false,
                data: 'scheduler_uuid 는 필수 값입니다.'
            });
        }

        // 3. 전달된 수정 항목만 골라서 유효성 검사 및 UpdateExpression 구성
        const updateParts = [];
        const expressionAttributeValues = {
            ':ownerUuid': ownerUuid
        };

        // (1) github_url 검증
        if (body.github_url !== undefined) {
            const githubUrl = String(body.github_url).trim();
            if (!githubUrl) {
                return respond(event, 400, {
                    result: false,
                    data: 'github_url 은 빈 값일 수 없습니다.'
                });
            }
            updateParts.push('github_url = :githubUrl');
            expressionAttributeValues[':githubUrl'] = githubUrl;
        }

        // (2) scheduler_day 검증: 월요일(0) ~ 일요일(6)
        if (body.scheduler_day !== undefined) {
            const rawDay = String(body.scheduler_day).trim();
            const schedulerDay = Number(rawDay);
            if (rawDay === '' || !Number.isInteger(schedulerDay) || schedulerDay < 0 || schedulerDay > 6) {
                return respond(event, 400, {
                    result: false,
                    data: 'scheduler_day 는 0(월요일)부터 6(일요일) 사이의 정수만 설정할 수 있습니다.'
                });
            }
            updateParts.push('scheduler_day = :schedulerDay');
            expressionAttributeValues[':schedulerDay'] = schedulerDay;
        }

        // (3) scheduler_time 검증: 1시(1) ~ 24시(24)
        if (body.scheduler_time !== undefined) {
            const rawTime = String(body.scheduler_time).trim();
            const schedulerTime = Number(rawTime);
            if (rawTime === '' || !Number.isInteger(schedulerTime) || schedulerTime < 1 || schedulerTime > 24) {
                return respond(event, 400, {
                    result: false,
                    data: 'scheduler_time 은 1(1시)부터 24(24시) 사이의 정수만 설정할 수 있습니다.'
                });
            }
            updateParts.push('scheduler_time = :schedulerTime');
            expressionAttributeValues[':schedulerTime'] = schedulerTime;
        }

        // (4) scheduler_status 검증: 비활성(0) 또는 활성(1)
        if (body.scheduler_status !== undefined) {
            const rawStatus = String(body.scheduler_status).trim();
            const schedulerStatus = Number(rawStatus);
            if (rawStatus === '' || !Number.isInteger(schedulerStatus) || (schedulerStatus !== 0 && schedulerStatus !== 1)) {
                return respond(event, 400, {
                    result: false,
                    data: 'scheduler_status 는 0(비활성) 또는 1(활성)만 설정할 수 있습니다.'
                });
            }
            updateParts.push('scheduler_status = :schedulerStatus');
            expressionAttributeValues[':schedulerStatus'] = schedulerStatus;
        }

        if (updateParts.length === 0) {
            return respond(event, 400, {
                result: false,
                data: '수정할 항목(github_url, scheduler_day, scheduler_time, scheduler_status 중 최소 1개)을 입력해주세요.'
            });
        }

        // 4. DynamoDB 에서 해당 scheduler_uuid 존재 및 소유권 확인
        const existing = await docClient.send(new GetCommand({
            TableName: TABLE_NAME,
            Key: {
                scheduler_uuid: schedulerUuid
            }
        }));

        if (!existing.Item) {
            return respond(event, 404, {
                result: false,
                data: `해당 scheduler_uuid(${schedulerUuid}) 정보를 찾을 수 없습니다.`
            });
        }

        if (String(existing.Item.user_uuid || '').trim() !== ownerUuid) {
            return respond(event, 403, {
                result: false,
                data: '해당 예약 항목을 수정할 권한이 없습니다.'
            });
        }

        // 5. 소유자 조건을 걸고 선택적 업데이트 후 user_uuid 제외 반환
        const updateResponse = await docClient.send(new UpdateCommand({
            TableName: TABLE_NAME,
            Key: {
                scheduler_uuid: schedulerUuid
            },
            UpdateExpression: `SET ${updateParts.join(', ')}`,
            ConditionExpression: 'user_uuid = :ownerUuid',
            ExpressionAttributeValues: expressionAttributeValues,
            ReturnValues: 'ALL_NEW'
        }));

        const { user_uuid: _hidden, ...publicAttributes } = updateResponse.Attributes ?? {};

        return respond(event, 200, {
            result: true,
            data: publicAttributes
        });
    }
    catch (error) {
        if (error?.name === 'ConditionalCheckFailedException') {
            return respond(event, 403, {
                result: false,
                data: '해당 예약 항목을 수정할 권한이 없습니다.'
            });
        }
        return respond(event, 500, {
            result: false,
            data: error.message
        });
    }
};