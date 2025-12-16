from pymongo import MongoClient, ASCENDING, DESCENDING
from datetime import datetime

# MongoDB 연결
client = MongoClient("mongodb://admin:admin123@localhost:27017/")
#이전 데이터베이스 삭제
client.drop_database('leak_database')
print("leak_database가 삭제되었습니다.")
db = client["leak_database"]
# 1. Source 컬렉션 스키마
source_schema = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": ["name", "type"],
        "properties": {
            "name": {
                "bsonType": "string",
                "description": "출처 이름 (필수)"
            },
            "type": {
                "bsonType": "string",
                "enum": ["darkweb", "surfaceweb", "telegram"],
                "description": "출처 타입 (필수)"
            },
            "description": {
                "bsonType": ["string", "null"],
                "description": "출처 설명"
            },
            "status": {
                "bsonType": "string",
                "enum": ["active", "inactive", "monitored"],
                "description": "상태"
            },
            "updated_at": {
                "bsonType": "date",
                "description": "수정 시각"
            }
        }
    }
}

# 2. Leaks 컬렉션 스키마
leaks_schema = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": ["source_id", "description", "leak_date"],
        "properties": {
            "source_id": {
                "bsonType": "objectId",
                "description": "출처 ID (source 컬렉션 참조)"
            },
            "original_link": {
                "bsonType": ["string", "null"],
                "description": "원본 링크"
            },
            "description": {
                "bsonType": "string",
                "description": "원본 텍스트 (필수)"
            },
            "leak_date": {
                "bsonType": "date",
                "description": "유출 날짜 (필수)"
            },
            "severity": {
                "bsonType": ["string", "null"],
                "enum": ["low", "medium", "high", "critical", None],
                "description": "심각도"
            },
            "created_at": {
                "bsonType": "date",
                "description": "생성 시각"
            },
            "updated_at": {
                "bsonType": ["date", "null"],
                "description": "수정 시각"
            },
            "status": {
                "bsonType": ["string", "null"],
                "enum": ["new", "processing", "investigating", "resolved", None],
                "description": "상태"
            }
        }
    }
}

# 3. File 컬렉션 스키마
file_schema = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": ["leak_id", "file_name", "index_name"],
        "properties": {
            "leak_id": {
                "bsonType": "objectId",
                "description": "유출 정보 ID (leaks 컬렉션 참조)"
            },
            "file_name": {
                "bsonType": "string",
                "description": "파일명 (필수)"
            },
            "index_name": {
                "bsonType": "string",
                "description": "Elasticsearch 인덱스 이름 (필수)"
            },
            "file_type": {
                "bsonType": ["string", "null"],
                "description": "파일 타입"
            },
            "hash_md5": {
                "bsonType": ["string", "null"],
                "description": "MD5 해시"
            },
            "hash_sha256": {
                "bsonType": ["string", "null"],
                "description": "SHA256 해시"
            },
            "uploaded_at": {
                "bsonType": "date",
                "description": "업로드 시각"
            }
        }
    }
}

# 컬렉션 생성 및 스키마 적용
collections_config = [
    ("sources", source_schema),
    ("leaks", leaks_schema),
    ("files", file_schema)
]

for collection_name, schema in collections_config:
    # 컬렉션 생성
    try:
        db.create_collection(collection_name)
        print(f"✓ 컬렉션 '{collection_name}' 생성 완료")
    except Exception as e:
        print(f"컬렉션 '{collection_name}' 이미 존재하거나 오류: {e}")
    
    # 스키마 검증 적용
    db.command("collMod", collection_name, validator=schema, validationLevel="moderate")
    print(f"✓ '{collection_name}' 스키마 검증 규칙 적용 완료")

print("\n=== MongoDB 스키마 설정 완료 ===")
print(f"데이터베이스: {db.name}")
print(f"생성된 컬렉션: source, leaks, file")