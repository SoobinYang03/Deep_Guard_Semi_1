# Leak Database Management System

Elasticsearch와 MongoDB를 활용한 데이터 유출 정보 관리 시스템 데모,예제

## 목차

- [프로젝트 구조](#프로젝트-구조)
- [기술 스택](#기술-스택)
- [설치 및 실행](#설치-및-실행)
- [API 문서](#api-문서)
- [데이터베이스 스키마](#데이터베이스-스키마)

## 프로젝트 구조

```
elastic/
├── main.py                    # FastAPI 서버
├── mongo_schema.py           # MongoDB 스키마 정의
├── insert_sample_data.py     # 샘플 데이터 삽입
├── docker-compose.yml        # Docker 컨테이너 설정
├── requirements.txt          # Python 패키지 목록
└── data/                     # 샘플 데이터 파일들
    ├── employee_records.tsv
    ├── login_attempts.csv
    ├── users_basic.csv
    └── ...
```

## 기술 스택

- **Backend**: FastAPI, Python 3.9+
- **Database**: 
  - Elasticsearch 8.11.1 (검색 및 분석)
  - MongoDB 7.0 (유출 정보 저장)
- **Visualization**: Kibana 8.11.1
- **Container**: Docker, Docker Compose

## 설치 및 실행

### 1. Docker 컨테이너 실행

```bash
docker-compose up -d
```

**실행되는 서비스:**
- Elasticsearch: http://localhost:9200
- Kibana: http://localhost:5601
- MongoDB: localhost:27017

### 2. Python 가상환경 설정

```bash
# 가상환경 생성
python -m venv venv
# or
python3 -m venv venv


# 패키지 설치
pip install -r requirements.txt
#or
pip3 install -r requirements.txt

# 가상환경 활성화 (Mac/Linux)
source venv/bin/activate
```

### 3. MongoDB 스키마 생성

```bash
python3 mongo_schema.py
```

### 4. 샘플 데이터 삽입

```bash
python3 insert_sample_data.py
```

### 5. FastAPI 서버 실행

```bash
uvicorn main:app --reload
```

서버 실행 후: http://localhost:8000

## 📡 API 문서

### Elasticsearch API

#### 1. 파일 업로드
```http
POST /upload
Content-Type: multipart/form-data

Parameters:
- file: 업로드할 파일 (CSV, TSV, JSON, NDJSON)
- index_name: 인덱스 이름 (선택, 기본값: 파일명)
```

#### 2. 인덱스 목록 조회
```http
GET /indices
```

#### 3. 인덱스 필드 조회
```http
GET /fields/{index_name}
```

#### 4. 데이터 조회
```http
GET /data/{index_name}?size=100&from_=0

Parameters:
- size: 조회할 문서 개수 (기본 100)
- from_: 시작 위치 (페이지네이션)
```

#### 5. 데이터 검색
```http
GET /search/{index_name}?query=검색어&field=필드명&min_score=1.0

Parameters:
- query: 검색어 (필수)
- field: 검색할 필드명 (선택)
- min_score: 최소 관련성 점수 (선택)
```

#### 6. 모든 인덱스에서 이메일 검색
```http
GET /search-all-indices?email=이메일주소&size=100

Parameters:
- email: 검색할 이메일 주소 (필수)
- size: 각 인덱스에서 가져올 최대 문서 개수 (기본 100)

```

#### 7. 헬스 체크
```http
GET /health
```

### API 문서 확인

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## 데이터베이스 스키마

### MongoDB Collections

#### 1. source (출처 정보)
```javascript
{
  _id: ObjectId,
  name: String,              // "telegram", "darkweb", etc.
  type: String,              // "social", "darkweb", "forum", "paste_site", "other"
  description: String,       // 출처 설명
  status: String,           // "active", "inactive", "monitored"
  created_at: Date
}
```

#### 2. leaks (유출 정보)
```javascript
{
  _id: ObjectId,
  source_id: ObjectId,      // source 컬렉션 참조
  original_link: String,    // 원본 링크 (unique)
  description: String,      // 원본 텍스트
  leak_date: Date,          // 유출 날짜
  severity: String,         // "low", "medium", "high", "critical"
  created_at: Date,
  updated_at: Date
}
```

#### 3. file (파일 정보)
```javascript
{
  _id: ObjectId,
  leak_id: ObjectId,        // leaks 컬렉션 참조
  file_name: String,        // 파일명
  file_path: String,        // 저장 경로
  file_type: String,        // "zip", "csv", "tsv", etc.
  hash_md5: String,         // MD5 해시
  hash_sha256: String,      // SHA256 해시
  uploaded_at: Date
}
```

### MongoDB 데이터 조회

**MongoDB Shell 접속:**
```bash
docker exec -it mongodb mongosh -u admin -p admin123
```

**기본 조회 명령어:**
```javascript
// 데이터베이스 선택
use leak_database

// 전체 데이터 조회
db.source.find().pretty()
db.leaks.find().pretty()
db.file.find().pretty()

// 개수 확인
db.leaks.countDocuments()

// 조건 검색
db.leaks.find({severity: "critical"}).pretty()

// Join 조회 (Aggregation)
db.leaks.aggregate([
  {
    $lookup: {
      from: "source",
      localField: "source_id",
      foreignField: "_id",
      as: "source_info"
    }
  }
])
```
## MongoDB Compass (GUI 도구)

MongoDB를 GUI로 관리하고 싶다면:

1. [MongoDB Compass 다운로드](https://www.mongodb.com/try/download/compass)
2. 연결 정보:
   ```
   mongodb://admin:admin123@localhost:27017/
   ```
## Docker 명령어

```bash
# 컨테이너 시작
docker-compose up -d

# 컨테이너 중지
docker-compose down

# 로그 확인
docker-compose logs -f

# 특정 서비스만 재시작
docker-compose restart mongodb
docker-compose restart elasticsearch

# 볼륨 포함 완전 삭제
docker-compose down -v
```



## 기본 인증 정보

### MongoDB
- Username: `admin`
- Password: `admin123`
- Port: `27017`

### Elasticsearch
- URL: `http://localhost:9200`
- 인증: 비활성화 (개발 환경)

  ⚠️ 주의: 최초 커밋 시 Git 에러 때문에 공용 레포에서 venv 폴더는 제외했습니다.
레포를 클론한 뒤에는 각자 로컬 환경에서 python -m venv venv로 가상환경을 다시 생성한 후, pip install -r requirements.txt를 실행해 주세요.
