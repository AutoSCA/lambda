import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand } from '@aws-sdk/lib-dynamodb';
import { S3Client, ListObjectsV2Command, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import crypto from 'crypto';

const region = process.env.AWS_REGION || 'ap-northeast-2';
const dynamoClient = new DynamoDBClient({ region });
const docClient = DynamoDBDocumentClient.from(dynamoClient);
const s3Client = new S3Client({ region });

const TABLE_NAME = process.env.DYNAMO_DB_TABLE_SANDBOX || 'gachon-p-project-sca-sandbox';
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
        // 1. 로그인 세션 필수 검증 (비로그인 PDF 다운로드 차단)
        const session = await resolveSession(event);
        if (!session) {
            return respond(event, 401, {
                result: false,
                data: 'PDF 다운로드는 로그인 후 이용할 수 있습니다.'
            });
        }

        const ownerUuid = String(session.user_uuid).trim();

        // 2. 쿼리 스트링(?sandbox_uuid=...)에서 sandbox_uuid 추출
        const sandboxUuid = String(
            event.queryStringParameters?.sandbox_uuid ?? event.sandbox_uuid ?? ''
        ).trim();

        if (!sandboxUuid) {
            return respond(event, 400, {
                result: false,
                data: 'sandbox_uuid 쿼리 스트링은 필수 값입니다.'
            });
        }

        // 3. DynamoDB 에서 해당 sandbox_uuid 존재·소유권·상태(7) 확인
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

        if (String(item.user_uuid || '').trim() !== ownerUuid) {
            return respond(event, 403, {
                result: false,
                data: '해당 보고서 PDF를 다운로드할 권한이 없습니다.'
            });
        }

        // sandbox_status 가 7(S3 업로드 완료)인 경우에만 S3 탐색 진행
        if (String(item.sandbox_status) !== '7') {
            return respond(event, 400, {
                result: false,
                sandbox_status: item.sandbox_status,
                data: `아직 보고서 업로드가 완료되지 않았습니다. (현재 상태: ${item.sandbox_status})`
            });
        }

        // 4. S3 에서 해당 sandbox_uuid/ 폴더 내 PDF 파일 탐색
        const listResponse = await s3Client.send(new ListObjectsV2Command({
            Bucket: BUCKET_NAME,
            Prefix: `${sandboxUuid}/`
        }));

        const pdfObject = (listResponse.Contents ?? []).find(
            (obj) => obj.Key && obj.Key.toLowerCase().endsWith('.pdf')
        );

        if (!pdfObject) {
            return respond(event, 404, {
                result: false,
                data: `해당 sandbox_uuid(${sandboxUuid}) 폴더에 PDF 파일이 존재하지 않습니다.`
            });
        }

        // 5. S3 Presigned 다운로드 URL 생성 (유효시간 1시간)
        const fileName = pdfObject.Key.split('/').pop() || 'report.pdf';
        const downloadUrl = await getSignedUrl(
            s3Client,
            new GetObjectCommand({
                Bucket: BUCKET_NAME,
                Key: pdfObject.Key,
                ResponseContentDisposition: `attachment; filename="${encodeURIComponent(fileName)}"`
            }),
            { expiresIn: 3600 }
        );

        return respond(event, 200, {
            result: true,
            download_url: downloadUrl
        });
    }
    catch (error) {
        return respond(event, 500, {
            result: false,
            data: error.message
        });
    }
};