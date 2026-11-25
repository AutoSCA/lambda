import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, DeleteCommand } from '@aws-sdk/lib-dynamodb';
import { S3Client, ListObjectsV2Command, DeleteObjectsCommand } from '@aws-sdk/client-s3';
import crypto from 'crypto';

const region = process.env.AWS_REGION || 'ap-northeast-2';
const dynamoClient = new DynamoDBClient({ region });
const docClient = DynamoDBDocumentClient.from(dynamoClient);
const s3Client = new S3Client({ region });

const TABLE_NAME = process.env.DYNAMO_DB_TABLE_SANDBOX || 'gachon-p-project-sca-sandbox';
const REPORT_TABLE_NAME = process.env.DYNAMO_DB_TABLE_REPORT || 'gachon-p-project-sca-report';
const SESSION_TABLE = process.env.DYNAMO_DB_TABLE_SESSION || 'gachon-p-project-sca-session';
const SESSION_COOKIE_NAME = process.env.SESSION_COOKIE_NAME || 'autosca_session';
const SESSION_TOKEN_PATTERN = /^[a-f0-9]{64}$/;
const BUCKET_NAME = process.env.S3_BUCKET || 'gachon-p-project-sca';

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

        // 3. DynamoDB 에서 해당 sandbox_uuid 존재·소유권·상태 확인
        const dynamoResponse = await docClient.send(new GetCommand({
            TableName: TABLE_NAME,
            Key: {
                sandbox_uuid: sandboxUuid
            }
        }));

        const item = dynamoResponse.Item;
        if (!item) {
            return respond(event, 404, {
                result: false,
                data: `해당 sandbox_uuid(${sandboxUuid}) 정보를 찾을 수 없습니다.`
            });
        }

        if (String(item.user_uuid || '').trim() !== requesterUuid) {
            return respond(event, 403, {
                result: false,
                data: '해당 항목을 삭제할 권한이 없습니다.'
            });
        }

        // 4. sandbox_status 가 7 이상인지 확인
        const statusNum = Number(item.sandbox_status);
        if (Number.isNaN(statusNum) || statusNum < 7) {
            return respond(event, 400, {
                result: false,
                sandbox_status: item.sandbox_status,
                data: `검사가 완료된 항목(status 7 이상)만 삭제할 수 있습니다. (현재 상태: ${item.sandbox_status})`
            });
        }

        // 5. S3 에서 해당 sandbox_uuid/ 폴더 내 파일 목록 조회 후 존재할 때만 통째로 삭제
        const listResponse = await s3Client.send(new ListObjectsV2Command({
            Bucket: BUCKET_NAME,
            Prefix: `${sandboxUuid}/`
        }));

        const s3Objects = listResponse.Contents ?? [];
        if (s3Objects.length > 0) {
            await s3Client.send(new DeleteObjectsCommand({
                Bucket: BUCKET_NAME,
                Delete: {
                    Objects: s3Objects.map((obj) => ({ Key: obj.Key })),
                    Quiet: true
                }
            }));
        }

        // 6. 소유자 조건을 걸고 DynamoDB(sandbox 테이블 + report 테이블) 에서 해당 행 함께 삭제
        await Promise.all([
            docClient.send(new DeleteCommand({
                TableName: TABLE_NAME,
                Key: {
                    sandbox_uuid: sandboxUuid
                },
                ConditionExpression: 'user_uuid = :ownerUuid',
                ExpressionAttributeValues: {
                    ':ownerUuid': requesterUuid
                }
            })),
            docClient.send(new DeleteCommand({
                TableName: REPORT_TABLE_NAME,
                Key: {
                    sandbox_uuid: sandboxUuid
                }
            }))
        ]);

        return respond(event, 200, {
            result: true,
            sandbox_uuid: sandboxUuid
        });
    }
    catch (error) {
        if (error?.name === 'ConditionalCheckFailedException') {
            return respond(event, 403, {
                result: false,
                data: '해당 항목을 삭제할 권한이 없습니다.'
            });
        }
        return respond(event, 500, {
            result: false,
            data: error.message
        });
    }
};