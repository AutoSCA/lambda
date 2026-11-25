import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import crypto from 'crypto';

const client = new DynamoDBClient({
    region: process.env.AWS_REGION || 'ap-northeast-2'
});
const docClient = DynamoDBDocumentClient.from(client);

const OTP_TABLE = process.env.DYNAMO_DB_TABLE_EMAIL_OTP || 'gachon-p-project-sca-email-otp';
const MAX_VERIFY_ATTEMPTS = Number(process.env.MAX_VERIFY_ATTEMPTS) || 5;
const VERIFICATION_TOKEN_TTL_SEC = Number(process.env.VERIFICATION_TOKEN_TTL_SEC) || 600;
const DYNAMO_TTL_BUFFER_SEC = 300;

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const CODE_PATTERN = /^\d{6}$/;
const VALID_PURPOSES = new Set(['signup', 'reset']);

const HEADERS = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
};

function respond(statusCode, payload) {
    return {
        statusCode,
        headers: HEADERS,
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

function buildOtpKey(email, purpose) {
    return purpose === 'reset' ? `reset#${email}` : email;
}

export const handler = async (event) => {
    // CORS Preflight(OPTIONS) 요청 처리
    if (event.requestContext?.http?.method === 'OPTIONS' || event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers: HEADERS, body: '' };
    }

    try {
        // 1. 요청 Body 파싱 및 기본 입력 검증
        let body;
        try {
            body = typeof event.body === 'string'
                ? JSON.parse(event.body || '{}')
                : (event.body ?? event ?? {});
        }
        catch {
            return respond(400, { result: false, data: '요청 JSON 형식이 올바르지 않습니다.' });
        }

        const email = body.email !== undefined ? String(body.email).trim().toLowerCase() : '';
        const code = body.code !== undefined ? String(body.code).trim() : '';
        const rawPurpose = body.purpose !== undefined && body.purpose !== null && String(body.purpose).trim() !== ''
            ? String(body.purpose).trim().toLowerCase()
            : 'signup';

        if (!VALID_PURPOSES.has(rawPurpose)) {
            return respond(400, { result: false, data: '올바르지 않은 인증 요청입니다.' });
        }
        const purpose = rawPurpose;

        if (!email || !EMAIL_PATTERN.test(email)) {
            return respond(400, { result: false, data: '올바른 이메일 형식을 입력해주세요.' });
        }
        if (!CODE_PATTERN.test(code)) {
            return respond(400, { result: false, data: '인증번호 6자리를 입력해주세요.' });
        }

        // 2. OTP 레코드 조회 (회원가입: email, 비밀번호 찾기: reset#${email})
        const otpKey = buildOtpKey(email, purpose);
        const response = await docClient.send(new GetCommand({
            TableName: OTP_TABLE,
            Key: { email: otpKey }
        }));

        const item = response.Item;
        if (!item || !item.code_hash || !item.code_salt || (item.purpose && item.purpose !== purpose)) {
            return respond(400, { result: false, data: '인증번호 요청 내역이 없습니다. 인증번호를 먼저 받아주세요.' });
        }

        const nowSec = Math.floor(Date.now() / 1000);

        // 3. 만료 및 시도 횟수 초과 확인
        if (nowSec > Number(item.expires_at ?? 0)) {
            return respond(400, { result: false, data: '인증번호가 만료되었습니다. 인증번호를 다시 받아주세요.' });
        }

        const attempts = Number(item.attempt_count ?? 0);
        if (attempts >= MAX_VERIFY_ATTEMPTS) {
            return respond(429, { result: false, data: '인증 시도 횟수를 초과했습니다. 인증번호를 다시 받아주세요.' });
        }

        // 4. 인증번호 해시 비교 (상수 시간 비교 수행 후, 더미 레코드이거나 불일치 시 동일하게 시도 횟수 증가)
        const expectedHash = sha256Hex(`${item.code_salt}:${code}`);
        const isMatch = safeHexEqual(expectedHash, item.code_hash);
        if (item.is_decoy === true || !isMatch) {
            await docClient.send(new UpdateCommand({
                TableName: OTP_TABLE,
                Key: { email: otpKey },
                UpdateExpression: 'SET attempt_count = if_not_exists(attempt_count, :zero) + :one',
                ExpressionAttributeValues: {
                    ':zero': 0,
                    ':one': 1
                }
            }));

            return respond(400, { result: false, data: '인증번호가 일치하지 않습니다.' });
        }

        // 5. 인증 성공 -> 3단계(비밀번호 설정/변경) 검증용 일회성 토큰 발급 및 저장
        const verificationToken = crypto.randomBytes(32).toString('hex');
        const tokenHash = sha256Hex(verificationToken);
        const tokenExpiresAt = nowSec + VERIFICATION_TOKEN_TTL_SEC;

        await docClient.send(new UpdateCommand({
            TableName: OTP_TABLE,
            Key: { email: otpKey },
            UpdateExpression:
                'SET verified = :verified, verification_token_hash = :tokenHash, token_expires_at = :tokenExpiresAt, #ttl = :ttl',
            ExpressionAttributeNames: {
                '#ttl': 'ttl'
            },
            ExpressionAttributeValues: {
                ':verified': true,
                ':tokenHash': tokenHash,
                ':tokenExpiresAt': tokenExpiresAt,
                ':ttl': tokenExpiresAt + DYNAMO_TTL_BUFFER_SEC
            }
        }));

        return respond(200, {
            result: true,
            verification_token: verificationToken
        });
    }
    catch (error) {
        return respond(500, {
            result: false,
            data: error.message
        });
    }
};