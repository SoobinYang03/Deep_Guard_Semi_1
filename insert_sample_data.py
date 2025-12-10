from pymongo import MongoClient
from datetime import datetime

# MongoDB 연결
client = MongoClient("mongodb://admin:admin123@localhost:27017/")
db = client["leak_database"]

#Source 데이터 삽입
sources = [
    {
        "name": "telegram",
        "type": "social",
        "description": "Telegram messaging platform",
        "status": "active",
        "created_at": datetime.utcnow()
    },
    {
        "name": "darkweb",
        "type": "darkweb",
        "description": "Dark web forums and markets",
        "status": "monitored",
        "created_at": datetime.utcnow()
    },
    {
        "name": "hackforum",
        "type": "forum",
        "description": "Hacking community forum",
        "status": "active",
        "created_at": datetime.utcnow()
    },
    {
        "name": "pastebin",
        "type": "paste_site",
        "description": "Text paste sharing site",
        "status": "active",
        "created_at": datetime.utcnow()
    }
]

print("=== Source 데이터 삽입 ===")
try:
    result = db.source.insert_many(sources)
    source_ids = result.inserted_ids
    print(f"✓ Source {len(source_ids)}건 삽입 완료")
except Exception as e:
    print(f"✗ Source 삽입 실패: {e}")
    # 이미 데이터가 있다면 기존 ID 사용
    source_ids = [doc["_id"] for doc in db.source.find()]
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
        "updated_at": None
    },
    {
        "source_id": source_ids[1],  # darkweb
        "original_link": "http://darkweb.onion/thread/98765",
        "description": "Login attempt logs with failed authentication records. Contains: user_id, ip_address, timestamp, success status. Multiple failed attempts from IP 203.0.113.5 detected. Users: gildong.hong, younghee.kim with detailed timestamps.",
        "leak_date": datetime(2024, 11, 18),
        "severity": "high",
        "created_at": datetime.utcnow(),
        "updated_at": None
    },
    {
        "source_id": source_ids[2],  # hackforum
        "original_link": "https://hackforum.com/threads/korean-users-db",
        "description": "Korean user personal information database.",
        "leak_date": datetime(2024, 11, 15),
        "severity": "high",
        "created_at": datetime.utcnow(),
        "updated_at": None
    },
    {
        "source_id": source_ids[3],  # pastebin
        "original_link": "https://pastebin.com/abc123xyz",
        "description": "Partial user contact information dump. Email addresses and phone numbers exposed. No file attachment, raw text paste only.",
        "leak_date": datetime(2024, 11, 10),
        "severity": "medium",
        "created_at": datetime.utcnow(),
        "updated_at": None
    },
    {
        "source_id": source_ids[0],  # telegram
        "original_link": "https://t.me/security_leaks_kr/777",
        "description": "Combined dataset with employee and user information. Cross-referenced data from multiple sources.",
        "leak_date": datetime(2024, 12, 1),
        "severity": "critical",
        "created_at": datetime.utcnow(),
        "updated_at": None
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

#File 데이터 삽입
files = [
    {
        "leak_id": leak_ids[0],
        "file_name": "employee_records.tsv",
        "file_path": "/data/leaks/2024/11/employee_records.tsv",
        "file_type": "tsv",
        "hash_md5": "d41d8cd98f00b204e9800998ecf8427e",
        "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "uploaded_at": datetime.utcnow()
    },
    {
        "leak_id": leak_ids[1],
        "file_name": "login_attempts.csv",
        "file_path": "/data/leaks/2024/11/login_attempts.csv",
        "file_type": "csv",
        "hash_md5": "098f6bcd4621d373cade4e832627b4f6",
        "hash_sha256": "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7",
        "uploaded_at": datetime.utcnow()
    },
    {
        "leak_id": leak_ids[2],
        "file_name": "users_basic.csv",
        "file_path": "/data/leaks/2024/11/users_basic.csv",
        "file_type": "csv",
        "hash_md5": "5d41402abc4b2a76b9719d911017c592",
        "hash_sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
        "uploaded_at": datetime.utcnow()
    },
    {
        "leak_id": leak_ids[4],
        "file_name": "combined_leak_2024.zip",
        "file_path": "/data/leaks/2024/12/combined_leak_2024.zip",
        "file_type": "zip",
        "hash_md5": "81dc9bdb52d04dc20036dbd8313ed055",
        "hash_sha256": "7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9",
        "uploaded_at": datetime.utcnow()
    }
]

print("\n=== File 데이터 삽입 ===")
try:
    result = db.file.insert_many(files)
    print(f"✓ File {len(result.inserted_ids)}건 삽입 완료")
except Exception as e:
    print(f"✗ File 삽입 실패: {e}")

print("\n=== 샘플 데이터 삽입 완료 ===")
print(f"Source: {len(sources)}건")
print(f"Leaks: {len(leaks)}건")
print(f"File: {len(files)}건")
