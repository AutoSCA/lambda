import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, PutCommand, DeleteCommand } from '@aws-sdk/lib-dynamodb';
import crypto from 'crypto';
import util from 'util';

const scryptAsync = util.promisify(crypto.scrypt);

const client = new DynamoDBClient({
    region: process.env.AWS_REGION || 'ap-northeast-2'
});
const docClient = DynamoDBDocumentClient.from(client);

const USER_TABLE = process.env.DYNAMO_DB_TABLE_USER || 'gachon-p-project-sca-user';
const OTP_TABLE = process.env.DYNAMO_DB_TABLE_EMAIL_OTP || 'gachon-p-project-sca-email-otp';

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const MIN_PASSWORD_LEN = 8;
const MAX_PASSWORD_LEN = 128;
const DEFAULT_USER_ROLE = 0;

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

function isValidPassword(pw) {
    if (typeof pw !== 'string') return false;
    if (pw.length < MIN_PASSWORD_LEN || pw.length > MAX_PASSWORD_LEN) return false;
    return (
        /[A-Z]/.test(pw) &&
        /[a-z]/.test(pw) &&
        /[0-9]/.test(pw) &&
        /[^A-Za-z0-9\s]/.test(pw)
    );
}

async function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const derived = await scryptAsync(password, salt, 64);
    return `scrypt$${salt}$${Buffer.from(derived).toString('hex')}`;
}

export const handler = async (event) => {
    // CORS Preflight(OPTIONS) 요청 처리
    if (event.requestContext?.http?.method === 'OPTIONS' || event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers: HEADERS, body: '' };
    }

    try {
        // 1. 요청 Body 파싱 및 입력 검증
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
        const password = typeof body.password === 'string' ? body.password : '';
        const verificationToken =
            body.verification_token !== undefined ? String(body.verification_token).trim() : '';

        if (!email || !EMAIL_PATTERN.test(email)) {
            return respond(400, { result: false, data: '올바른 이메일 형식을 입력해주세요.' });
        }
        if (!verificationToken) {
            return respond(400, { result: false, data: '이메일 인증이 필요합니다.' });
        }
        if (!isValidPassword(password)) {
            return respond(400, {
                result: false,
                data: '8자 이상, 영문 대소문자·숫자·특수기호를 모두 포함해주세요.'
            });
        }

        // 2. 이메일 인증 완료 여부 및 일회성 토큰 검증
        const otpResponse = await docClient.send(new GetCommand({
            TableName: OTP_TABLE,
            Key: { email }
        }));

        const otpItem = otpResponse.Item;
        const nowSec = Math.floor(Date.now() / 1000);

        if (
            !otpItem ||
            otpItem.is_decoy === true ||
            otpItem.verified !== true ||
            !otpItem.verification_token_hash ||
            nowSec > Number(otpItem.token_expires_at ?? 0)
        ) {
            return respond(401, {
                result: false,
                data: '이메일 인증이 만료되었거나 유효하지 않습니다. 다시 인증해주세요.'
            });
        }

        const tokenHash = sha256Hex(verificationToken);
        if (!safeHexEqual(tokenHash, otpItem.verification_token_hash)) {
            return respond(401, {
                result: false,
                data: '유효하지 않은 이메일 인증 토큰입니다.'
            });
        }

        // 3. 비밀번호 단방향 해시 생성 및 회원 테이블 저장 (created_at 제외, role은 서버에서 0 고정, 중복 가입 원자적 방지)
        const passwordHash = await hashPassword(password);
        const newUser = {
            email,
            user_uuid: crypto.randomUUID(),
            password_hash: passwordHash,
            role: DEFAULT_USER_ROLE
        };

        try {
            await docClient.send(new PutCommand({
                TableName: USER_TABLE,
                Item: newUser,
                ConditionExpression: 'attribute_not_exists(email)'
            }));
        }
        catch (putError) {
            if (putError?.name === 'ConditionalCheckFailedException') {
                return respond(409, { result: false, data: '회원가입을 완료할 수 없습니다. 다시 시도해주세요.' });
            }
            throw putError;
        }

        // 4. 사용 완료된 OTP 레코드 즉시 삭제 (토큰 재사용 방지)
        await docClient.send(new DeleteCommand({
            TableName: OTP_TABLE,
            Key: { email }
        })).catch(() => {});

        return respond(201, {
            result: true,
            user_uuid: newUser.user_uuid,
            email: newUser.email
        });
    }
    catch (error) {
        return respond(500, {
            result: false,
            data: error.message
        });
    }
};
