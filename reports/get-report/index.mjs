import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand } from '@aws-sdk/lib-dynamodb';
import crypto from 'crypto';
import zlib from 'zlib';

const client = new DynamoDBClient({
    region: process.env.AWS_REGION || 'ap-northeast-2'
});
const docClient = DynamoDBDocumentClient.from(client);

const REPORT_TABLE = process.env.DYNAMO_DB_TABLE_REPORT || 'gachon-p-project-sca-report';
const SANDBOX_TABLE = process.env.DYNAMO_DB_TABLE_SANDBOX || 'gachon-p-project-sca-sandbox';
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

// gzip 압축 저장된 Binary 보고서를 원본 JSON 객체로 복원
function decodeReport(raw) {
    if (raw instanceof Uint8Array || Buffer.isBuffer(raw)) {
        const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
        return JSON.parse(zlib.gunzipSync(buf).toString('utf8'));
    }
    if (typeof raw === 'string') {
        return JSON.parse(raw);
    }
    return raw;
}

export const handler = async (event) => {
    // CORS Preflight(OPTIONS) 요청 처리
    if (event.requestContext?.http?.method === 'OPTIONS' || event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers: buildHeaders(event), body: '' };
    }

    try {
        // 1. 쿼리 스트링(?sandbox_uuid=...)에서 sandbox_uuid 추출
        const sandboxUuid = String(
            event.queryStringParameters?.sandbox_uuid ?? event.sandbox_uuid ?? ''
        ).trim();

        if (!sandboxUuid) {
            return respond(event, 400, {
                result: false,
                data: 'sandbox_uuid 쿼리 스트링은 필수 값입니다.'
            });
        }

        // 2. 헤더 세션 쿠키 우선 확인 -> 세션이 없을 때만 쿼리 스트링의 user_uuid 확인
        const { hasCookie, session } = await resolveSession(event);
        let requesterUuid = '';

        if (session) {
            requesterUuid = String(session.user_uuid).trim();
        } else {
            const queryUserUuid = String(
                event.queryStringParameters?.user_uuid ?? event.user_uuid ?? ''
            ).trim();
            if (queryUserUuid) {
                requesterUuid = queryUserUuid;
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

        // 3. sandbox 테이블에서 소유권 확인 후 report 테이블에서 보고서 조회
        const [sandboxResponse, reportResponse] = await Promise.all([
            docClient.send(new GetCommand({
                TableName: SANDBOX_TABLE,
                Key: { sandbox_uuid: sandboxUuid }
            })),
            docClient.send(new GetCommand({
                TableName: REPORT_TABLE,
                Key: { sandbox_uuid: sandboxUuid }
            }))
        ]);

        const sandboxItem = sandboxResponse.Item;
        const nowSec = Math.floor(Date.now() / 1000);
        if (!sandboxItem || (sandboxItem.ttl !== undefined && nowSec > Number(sandboxItem.ttl))) {
            return respond(event, 404, {
                result: false,
                data: `해당 sandbox_uuid(${sandboxUuid})의 보고서 정보를 찾을 수 없습니다.`
            });
        }

        if (String(sandboxItem.user_uuid || '').trim() !== requesterUuid) {
            return respond(event, 403, {
                result: false,
                data: '해당 보고서를 조회할 권한이 없습니다.'
            });
        }

        const reportItem = reportResponse.Item;
        if (!reportItem || reportItem.report === undefined) {
            return respond(event, 404, {
                result: false,
                data: `해당 sandbox_uuid(${sandboxUuid})의 보고서 정보를 찾을 수 없습니다.`
            });
        }

        // 4. gzip 압축 해제 후 원본 JSON 반환
        const reportJson = decodeReport(reportItem.report);

        return respond(event, 200, {
            result: true,
            sandbox_uuid: reportItem.sandbox_uuid,
            data: reportJson
        });
    }
    catch (error) {
        return respond(event, 500, {
            result: false,
            data: error.message
        });
    }
};