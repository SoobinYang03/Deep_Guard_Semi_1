# DeepGuard React Dashboard

DeepGuard 프론트(React)입니다.

## 설치 및 실행

### 1. 의존성 설치

```bash
cd front
npm install
```

### 2. 개발 서버 실행

```bash
npm start
```

### 3. 프로덕션 빌드

```bash
npm run build
```

## 주요 기능

- **대시보드**: 위협 인텔리전스 요약 정보 및 차트
- **개인정보 유출 관리**: 계정/비밀번호 유출 목록 조회 및 상세 정보 확인
- **유출 정보 업로드**: CSV, JSON 등 다양한 포맷의 유출 데이터 일괄 업로드
- **유출 & OSINT**: OSINT 수집 및 URL 위협 분석
- **악성코드 탐지**: 파일 업로드 및 해시 검증
- **포트 스캐너**: 네트워크 포트 스캔 및 취약점 분석
- **설정**: 시스템 설정 및 환경 관리

## 환경 변수 설정

`.env` 파일을 생성하여 백엔드 API 주소를 설정하세요:

```env
REACT_APP_API_URL=http://localhost:5000
```