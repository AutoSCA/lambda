# AutoSCA Lambda

AutoSCA 웹 서비스(`https://autosca.cloud`)의 API Gateway · EventBridge 연동 AWS Lambda 함수(Node.js ESM, 외부 npm 의존성 없음) 모음입니다.
프론트엔드(React) 경로 기준으로 폴더를 분류해 관리합니다.

## 디렉터리 구조

| 폴더 (React 경로) | 함수 폴더 | 메서드 / 트리거 | 설명 |
| --- | --- | --- | --- |
| `home/` (`/`) | `post-sandbox` | `POST` | GitHub 저장소 취약점 진단 요청 등록 (게스트 24h TTL) |
| `running/` (`/running`) | `get-sandbox-status` | `GET` | 진행 중인 진단 항목 실시간 상태 조회 |
| `reports/` (`/reports`, `/failed`) | `get-sandbox-list` | `GET` | 전체 진단 목록 조회 (진단 중·완료·실패 공용) |
| `reports/` (`/reports/:uuid`) | `get-report` | `GET` | 취약점 진단 보고서 상세 JSON 조회 |
| `reports/` (`/reports`, `/reports/:uuid`) | `get-report-pdf` | `GET` | S3 PDF 보고서 Presigned URL 발급 (회원 전용) |
| `reports/` (`/reports`, `/failed`) | `delete-sandbox` | `DELETE` | 완료 보고서·실패 항목 및 S3 PDF 삭제 |
| `scheduler/` (`/scheduler`) | `get-scheduler-list` | `GET` | 주기적 진단 예약 목록 조회 |
| `scheduler/` (`/scheduler`) | `post-scheduler` | `POST` | 주기적 진단 예약 등록 |
| `scheduler/` (`/scheduler`) | `patch-scheduler` | `PATCH` | 예약 설정 수정 및 활성/비활성 토글 |
| `scheduler/` (`/scheduler`) | `delete-scheduler` | `DELETE` | 예약 삭제 |
| `scheduler/` (백엔드 스케줄) | `run-scheduler` | `EventBridge` | 매시간(KST) 활성 예약 항목 자동 진단 등록 |
| `login/` (`/login`) | `post-auth-login` | `POST` | 로그인 및 `HttpOnly` 세션 쿠키 발급 |
| `login/` (전역) | `get-auth-me` | `GET` | 세션 쿠키 기반 현재 로그인 상태 조회 |
| `login/` (전역) | `post-auth-logout` | `POST` | 서버 세션 폐기 및 쿠키 만료 |
| `signup/` (`/signup`, `/reset-password`) | `post-auth-send-code` | `POST` | 이메일 인증번호(OTP) 발송 (Resend API) |
| `signup/` (`/signup`, `/reset-password`) | `post-auth-verify-code` | `POST` | 이메일 인증번호 검증 및 일회성 토큰 발급 |
| `signup/` (`/signup`) | `post-auth-signup` | `POST` | 회원가입 완료 (`scrypt` 해싱) |
| `reset-password/` (`/reset-password`) | `post-auth-reset-password` | `POST` | 이메일 인증 기반 비밀번호 재설정 및 전체 세션 무효화 |
| `settings/` (`/settings`) | `post-auth-change-password` | `POST` | 로그인 상태 비밀번호 변경, 현재 세션 회전 및 타 기기 세션 폐기 |
| `settings/` (`/settings`) | `post-auth-delete-account` | `POST` | 회원 탈퇴 및 예약·진단·보고서·S3 PDF·세션·계정 일괄 삭제 |

## 주요 환경 변수

필수 시크릿을 제외한 리소스명·정책 값은 코드 기본값을 내장하고 있으며 필요 시 AWS Lambda 환경 변수로 재정의할 수 있습니다.

- **필수**: `RESEND_API_KEY` (`signup/post-auth-send-code`)
- **선택 (기본값 내장)**: `AWS_REGION`, `S3_BUCKET`, `DYNAMO_DB_TABLE_USER`, `DYNAMO_DB_TABLE_SESSION`, `DYNAMO_DB_TABLE_EMAIL_OTP`, `DYNAMO_DB_TABLE_SANDBOX`, `DYNAMO_DB_TABLE_REPORT`, `DYNAMO_DB_TABLE_SCHEDULER`, `ALLOWED_ORIGINS`, `SESSION_COOKIE_NAME`, `COOKIE_DOMAIN`, `COOKIE_SAME_SITE`, `SESSION_TTL_SEC`, `GUEST_SANDBOX_TTL_SEC`, `MAIL_FROM`, `OTP_TTL_SEC`, `VERIFICATION_TOKEN_TTL_SEC`, `MAX_VERIFY_ATTEMPTS`
