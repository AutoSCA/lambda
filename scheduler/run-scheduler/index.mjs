import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, ScanCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import crypto from 'crypto';

const client = new DynamoDBClient({
    region: process.env.AWS_REGION || 'ap-northeast-2'
});
const docClient = DynamoDBDocumentClient.from(client);

const SCHEDULER_TABLE = process.env.DYNAMO_DB_TABLE_SCHEDULER || 'gachon-p-project-sca-scheduler';
const SANDBOX_TABLE = process.env.DYNAMO_DB_TABLE_SANDBOX || 'gachon-p-project-sca-sandbox';

// 현재 한국 시간(KST, UTC+9) 기준 scheduler_day(월 0 ~ 일 6) 및 scheduler_time(1 ~ 24) 계산
// 자정(00시)은 전날의 24시로 매핑 (예: 월요일 24시 = 화요일 00시)
function getCurrentKstSchedule(now = new Date()) {
    const kst = new Date(now.getTime() + 9 * 60 * 60 * 1000);
    const jsDay = kst.getUTCDay(); // 0(일) ~ 6(토)
    const kstHour = kst.getUTCHours(); // 0 ~ 23

    const todayDay = (jsDay + 6) % 7; // 0(월) ~ 6(일)

    if (kstHour === 0) {
        return {
            schedulerDay: (todayDay + 6) % 7,
            schedulerTime: 24,
            kstIso: kst.toISOString().replace('Z', '+09:00')
        };
    }

    return {
        schedulerDay: todayDay,
        schedulerTime: kstHour,
        kstIso: kst.toISOString().replace('Z', '+09:00')
    };
}

// 스케줄러 테이블에서 조건에 맞는 항목 전체 조회 (페이지네이션 대응)
async function findTargetSchedulers(schedulerDay, schedulerTime) {
    const matchedItems = [];
    let lastEvaluatedKey;

    do {
        const response = await docClient.send(new ScanCommand({
            TableName: SCHEDULER_TABLE,
            FilterExpression:
                '(scheduler_status = :statusNum OR scheduler_status = :statusStr) ' +
                'AND (scheduler_day = :dayNum OR scheduler_day = :dayStr) ' +
                'AND (scheduler_time = :timeNum OR scheduler_time = :timeStr)',
            ExpressionAttributeValues: {
                ':statusNum': 1,
                ':statusStr': '1',
                ':dayNum': schedulerDay,
                ':dayStr': String(schedulerDay),
                ':timeNum': schedulerTime,
                ':timeStr': String(schedulerTime)
            },
            ExclusiveStartKey: lastEvaluatedKey
        }));

        if (Array.isArray(response.Items)) {
            matchedItems.push(...response.Items);
        }
        lastEvaluatedKey = response.LastEvaluatedKey;
    } while (lastEvaluatedKey);

    return matchedItems;
}

export const handler = async (event = {}) => {
    try {
        // 1. 실행 대상 요일/시간 결정 (콘솔 테스트 시 event.scheduler_day / event.scheduler_time 지정 가능)
        const current = getCurrentKstSchedule();
        const schedulerDay = event.scheduler_day !== undefined ? Number(event.scheduler_day) : current.schedulerDay;
        const schedulerTime = event.scheduler_time !== undefined ? Number(event.scheduler_time) : current.schedulerTime;

        if (
            !Number.isInteger(schedulerDay) || schedulerDay < 0 || schedulerDay > 6 ||
            !Number.isInteger(schedulerTime) || schedulerTime < 1 || schedulerTime > 24
        ) {
            throw new Error(`유효하지 않은 요일(${schedulerDay}) 또는 시간(${schedulerTime}) 값입니다.`);
        }

        // 2. 스케줄러 테이블에서 활성(1) + 현재 요일 + 현재 시간에 해당하는 항목 조회
        const targets = await findTargetSchedulers(schedulerDay, schedulerTime);

        // 3. 조건에 맞는 각 항목을 샌드박스 테이블에 상태 '0' 으로 등록
        const results = await Promise.allSettled(
            targets.map(async (item) => {
                const userUuid = item.user_uuid !== undefined ? String(item.user_uuid).trim() : '';
                const githubUrl = item.github_url !== undefined ? String(item.github_url).trim() : '';

                if (!userUuid || !githubUrl) {
                    throw new Error(`필수 필드 누락 (scheduler_uuid: ${item.scheduler_uuid})`);
                }

                const newSandboxItem = {
                    sandbox_uuid: crypto.randomUUID(),
                    user_uuid: userUuid,
                    github_url: githubUrl,
                    sandbox_status: '0',
                    created_at: Math.floor(Date.now() / 1000)
                };

                await docClient.send(new PutCommand({
                    TableName: SANDBOX_TABLE,
                    Item: newSandboxItem,
                    ConditionExpression: 'attribute_not_exists(sandbox_uuid)'
                }));

                return {
                    scheduler_uuid: item.scheduler_uuid,
                    sandbox_uuid: newSandboxItem.sandbox_uuid,
                    user_uuid: userUuid,
                    github_url: githubUrl,
                    created_at: newSandboxItem.created_at
                };
            })
        );

        const created = [];
        const failed = [];

        results.forEach((res, idx) => {
            if (res.status === 'fulfilled') {
                created.push(res.value);
            } else {
                failed.push({
                    scheduler_uuid: targets[idx]?.scheduler_uuid ?? null,
                    error: res.reason?.message || String(res.reason)
                });
            }
        });

        const summary = {
            result: true,
            kst_time: current.kstIso,
            scheduler_day: schedulerDay,
            scheduler_time: schedulerTime,
            matched_count: targets.length,
            created_count: created.length,
            failed_count: failed.length,
            created,
            failed
        };

        console.log('[run-scheduler] 실행 완료:', JSON.stringify(summary));
        return summary;
    }
    catch (error) {
        console.error('[run-scheduler] 오류 발생:', error);
        return {
            result: false,
            data: error.message
        };
    }
};