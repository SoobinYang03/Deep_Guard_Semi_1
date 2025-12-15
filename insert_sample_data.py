from pymongo import MongoClient
from datetime import datetime
from elasticsearch import Elasticsearch, helpers
import pandas as pd
import os

# MongoDB 연결
client = MongoClient("mongodb://admin:admin123@localhost:27017/")
db = client["leak_database"]

# Elasticsearch 연결
es = Elasticsearch(
    "http://localhost:9200",
    verify_certs=False
)

# 데이터 파일 경로
DATA_DIR = "./data"

def upload_to_elasticsearch(file_path, index_name):
    """파일을 읽어서 Elasticsearch에 업로드"""
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()
    
    try:
        if ext == '.csv':
            df = pd.read_csv(file_path)
        elif ext == '.tsv':
            df = pd.read_csv(file_path, sep='\t')
        elif ext == '.json':
            df = pd.read_json(file_path)
        elif ext == '.ndjson':
            df = pd.read_json(file_path, lines=True)
        else:
            print(f"  ✗ 지원하지 않는 파일 형식: {ext}")
            return 0, 0
        
        # DataFrame을 Elasticsearch에 bulk insert
        def doc_generator(df, index_name):
            for idx, row in df.iterrows():
                yield {
                    "_index": index_name,
                    "_source": row.to_dict()
                }
        
        success, failed = helpers.bulk(es, doc_generator(df, index_name))
        print(f"  ✓ {file_path} → {index_name}: {success}건 성공, {failed}건 실패")
        return success, failed
    except Exception as e:
        print(f"  ✗ {file_path} 업로드 실패: {e}")
        return 0, 0

#Source 데이터 삽입
sources = [
    {
        "name": "joker_channel",
        "type": "telegram",
        "description": "Telegram messaging platform",
        "status": "active",
        "updated_at": datetime.utcnow()
    },
    {
        "name": "darkforums",
        "type": "darkweb",
        "description": "Dark web forums for data leaks",
        "status": "monitored",
        "updated_at": datetime.utcnow()
    },
    {
        "name": "hackforum",
        "type": "darkweb",
        "description": "Hacking community forum",
        "status": "active",
        "updated_at": datetime.utcnow()
    },
    {
        "name": "pastebin",
        "type": "surfaceweb",
        "description": "Text paste sharing site",
        "status": "active",
        "updated_at": datetime.utcnow()
    }
]

print("=== Source 데이터 삽입 ===")
try:
    result = db.sources.insert_many(sources)
    source_ids = result.inserted_ids
    print(f"✓ Source {len(source_ids)}건 삽입 완료")
except Exception as e:
    print(f"✗ Source 삽입 실패: {e}")
    # 이미 데이터가 있다면 기존 ID 사용
    source_ids = [doc["_id"] for doc in db.sources.find()]
    print(f"기존 Source 사용: {len(source_ids)}건")

#Leaks 데이터 삽입
leaks = [
    {
        "source_id": source_ids[0],  # telegram
        "original_link": "https://t.me/leakdb/12345",
        "description": "Employee database leaked from major tech company. Contains: Employee_ID, Name, Department, Position, Salary, Join_Date, Email. Sample: E001 Gil-dong Hong Engineering Senior Developer 75000000 2020-03-15 hong.gildong@company.com",
        "leak_date": datetime(2024, 11, 20),
        "severity": "critical",
        "created_at": datetime.utcnow(),
        "updated_at": None,
        "status": "new"
    },
    {
        "source_id": source_ids[1],  # darkweb
        "original_link": "http://darkweb.onion/thread/98765",
        "description": "Login attempt logs with failed authentication records. Contains: user_id, ip_address, timestamp, success status. Multiple failed attempts from IP 203.0.113.5 detected. Users: gildong.hong, younghee.kim with detailed timestamps.",
        "leak_date": datetime(2024, 11, 18),
        "severity": "high",
        "created_at": datetime.utcnow(),
        "updated_at": None,
        "status": "processing"

    },
    {
        "source_id": source_ids[2],  # hackforum
        "original_link": "https://hackforum.com/threads/korean-users-db",
        "description": "Korean user personal information database.",
        "leak_date": datetime(2024, 11, 15),
        "severity": "high",
        "created_at": datetime.utcnow(),
        "updated_at": None,
        "status": "investigating"
    },
    {
        "source_id": source_ids[3],  # pastebin
        "original_link": "https://pastebin.com/abc123xyz",
        "description": "Partial user contact information dump. Email addresses and phone numbers exposed. No file attachment, raw text paste only.",
        "leak_date": datetime(2024, 11, 10),
        "severity": "medium",
        "created_at": datetime.utcnow(),
        "updated_at": None,
        "status": "resolved"
    },
    {
        "source_id": source_ids[0],  # telegram
        "original_link": "https://t.me/security_leaks_kr/777",
        "description": "Combined dataset with employee and user information. Cross-referenced data from multiple sources.",
        "leak_date": datetime(2024, 12, 1),
        "severity": "critical",
        "created_at": datetime.utcnow(),
        "updated_at": None,
        "status": "new"
    }
]

print("\n=== Leaks 데이터 삽입 ===")
try:
    result = db.leaks.insert_many(leaks)
    leak_ids = result.inserted_ids
    print(f"✓ Leaks {len(leak_ids)}건 삽입 완료")
except Exception as e:
    print(f"✗ Leaks 삽입 실패: {e}")
    leak_ids = [doc["_id"] for doc in db.leaks.find()]
    print(f"기존 Leaks 사용: {len(leak_ids)}건")

#File 데이터 삽입 및 Elasticsearch 업로드
files_data = [
    {
        "leak_id": leak_ids[0],
        "file_name": "employee_records.tsv",
        "file_type": "tsv",
        "file_path": os.path.join(DATA_DIR, "employee_records.tsv")
    },
    {
        "leak_id": leak_ids[1],
        "file_name": "login_attempts.csv",
        "file_type": "csv",
        "file_path": os.path.join(DATA_DIR, "login_attempts.csv")
    },
    {
        "leak_id": leak_ids[2],
        "file_name": "users_basic.csv",
        "file_type": "csv",
        "file_path": os.path.join(DATA_DIR, "users_basic.csv")
    },
    {
        "leak_id": leak_ids[3],
        "file_name": "users_contact.ndjson",
        "file_type": "ndjson",
        "file_path": os.path.join(DATA_DIR, "users_contact.ndjson")
    },
    {
        "leak_id": leak_ids[4],
        "file_name": "purchase_history.ndjson",
        "file_type": "ndjson",
        "file_path": os.path.join(DATA_DIR, "purchase_history.ndjson")
    },
    {
        "leak_id": leak_ids[4],
        "file_name": "sample.json",
        "file_type": "json",
        "file_path": os.path.join(DATA_DIR, "sample.json")
    },
]

print("\n=== Elasticsearch 인덱싱 및 File 데이터 삽입 ===")
files = []

for file_data in files_data:
    file_path = file_data["file_path"]
    
    # leak_id 기반으로 인덱스 이름 생성
    index_name = f"leak_{str(file_data['leak_id'])}"
    
    # 파일이 존재하면 ES에 업로드
    if os.path.exists(file_path):
        print(f"\n{file_data['file_name']} 처리 중...")
        success, failed = upload_to_elasticsearch(file_path, index_name)
        
        # MongoDB에 저장할 파일 정보
        file_doc = {
            "leak_id": file_data["leak_id"],
            "file_name": file_data["file_name"],
            "file_type": file_data["file_type"],
            "index_name": index_name,
            "hash_md5": "d41d8cd98f00b204e9800998ecf8427e",  # 샘플 해시
            "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # 샘플 해시
            "uploaded_at": datetime.utcnow()
        }
        files.append(file_doc)
    else:
        print(f"\n✗ 파일 없음: {file_path}")

print("\n=== MongoDB File 컬렉션 저장 ===")
try:
    if files:
        result = db.files.insert_many(files)
        print(f"✓ File {len(result.inserted_ids)}건 삽입 완료")
    else:
        print("✗ 저장할 파일 없음")
except Exception as e:
    print(f"✗ File 삽입 실패: {e}")

print("\n=== 샘플 데이터 삽입 완료 ===")
print(f"Source: {len(sources)}건")
print(f"Leaks: {len(leaks)}건")
print(f"Files & ES Indices: {len(files)}건")
print("\n생성된 Elasticsearch 인덱스:")
for file_doc in files:
    print(f"  - {file_doc['index_name']} ({file_doc['file_name']})")
