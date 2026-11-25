import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
    DynamoDBDocumentClient,
    GetCommand,
    DeleteCommand,
    ScanCommand
} from '@aws-sdk/lib-dynamodb';
import { S3Client, ListObjectsV2Command, DeleteObjectsCommand } from '@aws-sdk/client-s3';
import crypto from 'crypto';
import util from 'util';

const scryptAsync = util.promisify(crypto.scrypt);

const region = process.env.AWS_REGION || 'ap-northeast-2';
const dynamoClient = new DynamoDBClient({ region });
const docClient = DynamoDBDocumentClient.from(dynamoClient);
const s3Client = new S3Client({ region });

const USER_TABLE = process.env.DYNAMO_DB_TABLE_USER || 'gachon-p-project-sca-user';
const SESSION_TABLE = process.env.DYNAMO_DB_TABLE_SESSION || 'gachon-p-project-sca-session';
const OTP_TABLE = process.env.DYNAMO_DB_TABLE_EMAIL_OTP || 'gachon-p-project-sca-email-otp';
const SANDBOX_TABLE = process.env.DYNAMO_DB_TABLE_SANDBOX || 'gachon-p-project-sca-sandbox';
const REPORT_TABLE = process.env.DYNAMO_DB_TABLE_REPORT || 'gachon-p-project-sca-report';
const SCHEDULER_TABLE = process.env.DYNAMO_DB_TABLE_SCHEDULER || 'gachon-p-project-sca-scheduler';
const BUCKET_NAME = process.env.S3_BUCKET || 'gachon-p-project-sca';

const SESSION_COOKIE_NAME = process.env.SESSION_COOKIE_NAME || 'autosca_session';
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN !== undefined ? process.env.COOKIE_DOMAIN : '.autosca.cloud';
const COOKIE_SAME_SITE = process.env.COOKIE_SAME_SITE || 'Lax';

const SESSION_TOKEN_PATTERN = /^[a-f0-9]{64}$/;
const MAX_PASSWORD_LEN = 128;
const DUMMY_SALT = '00000000000000000000000000000000';
const DUMMY_DERIVED_HEX = '0'.repeat(128);
const CLEANUP_CONCURRENCY = 10;

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

async function runWithConcurrency(items, limit, worker) {
    if (items.length === 0) return;
    let index = 0;
    const runnerCount = Math.min(limit, items.length);

    await Promise.all(
        Array.from({ length: runnerCount }, async () => {
            while (index < items.length) {
                const current = items[index++];
                await worker(current);
            }
        })
    );
}

async function scanOwnedKeys(tableName, keyAttr, userUuid) {
    const keys = [];
    let exclusiveStartKey;

    do {
        const res = await docClient.send(new ScanCommand({
            TableName: tableName,
            FilterExpression: 'user_uuid = :userUuid',
            ExpressionAttributeValues: {
                ':userUuid': userUuid
            },
            ProjectionExpression: keyAttr,
            ...(exclusiveStartKey ? { ExclusiveStartKey: exclusiveStartKey } : {})
        }));

        for (const item of res.Items ?? []) {
            const val = item?.[keyAttr];
            if (typeof val === 'string' && val.trim()) {
                keys.push(val.trim());
            }
        }
        exclusiveStartKey = res.LastEvaluatedKey;
    } while (exclusiveStartKey);

    return keys;
}

async function deleteS3Prefix(prefix) {
    let continuationToken;

    do {
        const listRes = await s3Client.send(new ListObjectsV2Command({
            Bucket: BUCKET_NAME,
            Prefix: prefix,
            ...(continuationToken ? { ContinuationToken: continuationToken } : {})
        }));

        const objects = (listRes.Contents ?? [])
            .map((obj) => obj.Key)
            .filter((key) => typeof key === 'string' && key.length > 0);

        for (let i = 0; i < objects.length; i += 1000) {
            const chunk = objects.slice(i, i + 1000).map((Key) => ({ Key }));
            await s3Client.send(new DeleteObjectsCommand({
                Bucket: BUCKET_NAME,
                Delete: {
                    Objects: chunk,
                    Quiet: true
                }
            }));
        }

        continuationToken = listRes.IsTruncated ? listRes.NextContinuationToken : undefined;
    } while (continuationToken);
}

async function invalidateAllUserSessions(email, userUuid) {
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
            if (item?.session_id) sessionIds.push(item.session_id);
        }
        exclusiveStartKey = scanRes.LastEvaluatedKey;
    } while (exclusiveStartKey);

    await runWithConcurrency(sessionIds, CLEANUP_CONCURRENCY, (sessionId) =>
        docClient.send(new DeleteCommand({
            TableName: SESSION_TABLE,
            Key: { session_id: sessionId }
        }))
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

        // 2. 요청 Body 파싱 및 비밀번호 입력 검증
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

        const password = typeof body.password === 'string' ? body.password : '';
        if (!password) {
            return respond(event, 400, {
                result: false,
                code: 'PASSWORD_REQUIRED',
                data: '비밀번호를 입력해주세요.'
            });
        }
        if (password.length > MAX_PASSWORD_LEN) {
            return respond(event, 403, {
                result: false,
                code: 'INVALID_PASSWORD',
                data: '비밀번호가 올바르지 않습니다.'
            });
        }

        // 3. 회원 조회 및 비밀번호 재검증
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

        const isPasswordValid = await verifyPassword(password, user.password_hash);
        if (!isPasswordValid) {
            return respond(event, 403, {
                result: false,
                code: 'INVALID_PASSWORD',
                data: '비밀번호가 올바르지 않습니다.'
            });
        }

        // 4. 사용자의 모든 예약(scheduler) 삭제 (신규 예약 진단 실행 차단)
        const schedulerUuids = await scanOwnedKeys(SCHEDULER_TABLE, 'scheduler_uuid', sessionUserUuid);
        await runWithConcurrency(schedulerUuids, CLEANUP_CONCURRENCY, (schedulerUuid) =>
            docClient.send(new DeleteCommand({
                TableName: SCHEDULER_TABLE,
                Key: { scheduler_uuid: schedulerUuid },
                ConditionExpression: 'attribute_not_exists(scheduler_uuid) OR user_uuid = :userUuid',
                ExpressionAttributeValues: {
                    ':userUuid': sessionUserUuid
                }
            }))
        );

        // 5. 사용자의 모든 진단(sandbox), 보고서(report), S3 PDF 파일 삭제
        const sandboxUuids = await scanOwnedKeys(SANDBOX_TABLE, 'sandbox_uuid', sessionUserUuid);
        await runWithConcurrency(sandboxUuids, CLEANUP_CONCURRENCY, async (sandboxUuid) => {
            await deleteS3Prefix(`${sandboxUuid}/`);
            await Promise.all([
                docClient.send(new DeleteCommand({
                    TableName: REPORT_TABLE,
                    Key: { sandbox_uuid: sandboxUuid }
                })),
                docClient.send(new DeleteCommand({
                    TableName: SANDBOX_TABLE,
                    Key: { sandbox_uuid: sandboxUuid },
                    ConditionExpression: 'attribute_not_exists(sandbox_uuid) OR user_uuid = :userUuid',
                    ExpressionAttributeValues: {
                        ':userUuid': sessionUserUuid
                    }
                }))
            ]);
        });

        // 6. 회원 레코드 원자적 삭제
        try {
            await docClient.send(new DeleteCommand({
                TableName: USER_TABLE,
                Key: { email: sessionEmail },
                ConditionExpression: 'attribute_exists(email) AND user_uuid = :userUuid',
                ExpressionAttributeValues: {
                    ':userUuid': sessionUserUuid
                }
            }));
        }
        catch (deleteError) {
            if (deleteError?.name === 'ConditionalCheckFailedException') {
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
            throw deleteError;
        }

        // 7. 모든 로그인 세션 및 잔여 OTP 레코드 정리 후 세션 쿠키 만료
        await Promise.allSettled([
            invalidateAllUserSessions(sessionEmail, sessionUserUuid),
            docClient.send(new DeleteCommand({
                TableName: OTP_TABLE,
                Key: { email: sessionEmail }
            })),
            docClient.send(new DeleteCommand({
                TableName: OTP_TABLE,
                Key: { email: `reset#${sessionEmail}` }
            }))
        ]);

        return respond(
            event,
            200,
            { result: true },
            { 'Set-Cookie': buildClearSessionCookie() }
        );
    }
    catch (error) {
        return respond(event, 500, {
            result: false,
            data: error.message
        });
    }
};