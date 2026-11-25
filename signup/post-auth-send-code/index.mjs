import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, PutCommand, DeleteCommand } from '@aws-sdk/lib-dynamodb';
import crypto from 'crypto';

const client = new DynamoDBClient({
    region: process.env.AWS_REGION || 'ap-northeast-2'
});
const docClient = DynamoDBDocumentClient.from(client);

const USER_TABLE = process.env.DYNAMO_DB_TABLE_USER || 'gachon-p-project-sca-user';
const OTP_TABLE = process.env.DYNAMO_DB_TABLE_EMAIL_OTP || 'gachon-p-project-sca-email-otp';
const MAIL_FROM = process.env.MAIL_FROM || 'AutoSCA <no-reply@autosca.cloud>';
const OTP_TTL_SEC = Number(process.env.OTP_TTL_SEC) || 180;
const DYNAMO_TTL_BUFFER_SEC = 900;
const FAKE_SEND_DELAY_MIN_MS = 220;
const FAKE_SEND_DELAY_MAX_MS = 480;

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
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

function hashOtpCode(salt, code) {
    return crypto.createHash('sha256').update(`${salt}:${code}`).digest('hex');
}

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function buildOtpKey(email, purpose) {
    return purpose === 'reset' ? `reset#${email}` : email;
}

async function sendOtpEmailViaResend(apiKey, toEmail, code, purpose) {
    const subject = purpose === 'reset'
        ? '[AutoSCA] 비밀번호 찾기 인증번호'
        : '[AutoSCA] 이메일 인증번호';

    const res = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${apiKey}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            from: MAIL_FROM,
            to: [toEmail],
            subject,
            text: code
        })
    });

    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
        const message = data?.message || data?.error || `Resend API 오류 (${res.status})`;
        throw new Error(message);
    }
    return data;
}

export const handler = async (event) => {
    // CORS Preflight(OPTIONS) 요청 처리
    if (event.requestContext?.http?.method === 'OPTIONS' || event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers: HEADERS, body: '' };
    }

    try {
        // 1. 요청 Body 파싱 및 이메일·용도(purpose) 검증
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
        const rawPurpose = body.purpose !== undefined && body.purpose !== null && String(body.purpose).trim() !== ''
            ? String(body.purpose).trim().toLowerCase()
            : 'signup';

        if (!VALID_PURPOSES.has(rawPurpose)) {
            return respond(400, { result: false, data: '올바르지 않은 인증 요청입니다.' });
        }
        const purpose = rawPurpose;

        if (!email) {
            return respond(400, { result: false, data: '이메일을 입력해주세요.' });
        }
        if (!EMAIL_PATTERN.test(email)) {
            return respond(400, { result: false, data: '올바른 이메일 형식을 입력해주세요.' });
        }

        const resendApiKey = process.env.RESEND_API_KEY?.trim();
        if (!resendApiKey) {
            return respond(500, { result: false, data: 'RESEND_API_KEY 환경변수가 설정되지 않았습니다.' });
        }

        // 2. 가입 여부 확인 (계정 열거 공격 방지: 존재 여부를 응답/타이밍/verify-code로 노출하지 않음)
        //    - signup: 이미 가입된 이메일이면 decoy 저장
        //    - reset : 가입되지 않은 이메일이면 decoy 저장
        const existingUser = await docClient.send(new GetCommand({
            TableName: USER_TABLE,
            Key: { email }
        }));

        const otpKey = buildOtpKey(email, purpose);
        const nowSec = Math.floor(Date.now() / 1000);
        const expiresAt = nowSec + OTP_TTL_SEC;
        const shouldUseDecoy = purpose === 'reset' ? !existingUser.Item : Boolean(existingUser.Item);

        if (shouldUseDecoy) {
            // 실제 메일은 발송하지 않되, verify-code 조회/오답 카운트/429 동작까지 동일하게 유지하기 위해
            // 절대 통과할 수 없는 더미(decoy) OTP 레코드를 저장하고 실제 메일 발송과 유사한 지연 후 200 반환
            await docClient.send(new PutCommand({
                TableName: OTP_TABLE,
                Item: {
                    email: otpKey,
                    purpose,
                    code_salt: crypto.randomBytes(16).toString('hex'),
                    code_hash: crypto.randomBytes(32).toString('hex'),
                    expires_at: expiresAt,
                    attempt_count: 0,
                    verified: false,
                    is_decoy: true,
                    ttl: expiresAt + DYNAMO_TTL_BUFFER_SEC
                }
            }));

            await sleep(crypto.randomInt(FAKE_SEND_DELAY_MIN_MS, FAKE_SEND_DELAY_MAX_MS + 1));

            return respond(200, {
                result: true,
                expires_in: OTP_TTL_SEC
            });
        }

        // 3. 6자리 인증번호 생성 및 해시 저장 (재발송 시 기존 행 덮어쓰기)
        const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
        const codeSalt = crypto.randomBytes(16).toString('hex');
        const codeHash = hashOtpCode(codeSalt, code);

        await docClient.send(new PutCommand({
            TableName: OTP_TABLE,
            Item: {
                email: otpKey,
                purpose,
                code_salt: codeSalt,
                code_hash: codeHash,
                expires_at: expiresAt,
                attempt_count: 0,
                verified: false,
                is_decoy: false,
                ttl: expiresAt + DYNAMO_TTL_BUFFER_SEC
            }
        }));

        // 4. Resend API로 인증번호 이메일 발송 (실패 시 저장한 OTP 정리)
        try {
            await sendOtpEmailViaResend(resendApiKey, email, code, purpose);
        }
        catch (mailError) {
            await docClient.send(new DeleteCommand({
                TableName: OTP_TABLE,
                Key: { email: otpKey }
            })).catch(() => { });

            return respond(502, {
                result: false,
                data: `인증 메일 발송에 실패했습니다: ${mailError.message}`
            });
        }

        return respond(200, {
            result: true,
            expires_in: OTP_TTL_SEC
        });
    }
    catch (error) {
        return respond(500, {
            result: false,
            data: error.message
        });
    }
};