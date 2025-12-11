DeepGuard B2B Crawler

기업 도메인을 기반으로 텔레그램과 다크웹상의 위협 정보를 실시간으로 수집·분석하는 인텔리전스 모듈입니다.
4가지 레이어를 활용하여 유출 여부를 진단합니다.
단순한 검색을 넘어, 생성형 AI(Google Gemini)를 활용한 경쟁사 분석과 Tor 네트워크를 통한 심층 웹 스캔을 통해 기업의 잠재적 보안 위협을 입체적으로 탐지합니다.


1. 이메일 주소 기반 
검색 타겟 : 텔레그램 해커 채널, 다크웹 미러링 사이트, Tor기반 실제 다크웹 사이트
검색 방식 : 입력받은 이메일 + 위협 키워드 (Password, Combo, Stealer, Auth 등)
검색 목적 : 임직원의 ID/PW가 해커들에게 유출되었는지 실시간 감지

2. 도메인 주소 기반
검색 타겟 : 텔레그램 해커 채널, 다크웹 미러링 사이트, Tor기반 실제 다크웹 사이트
검색 방식 : 입력받은 이메일의 도메인 주소 + 보안 키워드 (Admin, Root, Confidential, VPN, Backup 등)
검색 목적 : 관리자 권한, 대외비 문서, 백업 파일 등 치명적인 자산 노출 여부 식별

3. 회사이름 기반
검색 타겟 : 랜섬웨어 뉴스 채널
검색 방식 : AI 분석.Google Gemini가 기업명을 분석하여 주요 경쟁사 리스트 자동 산출. 자사 및 경쟁사 이름으로 랜섬웨어 그룹의 피해 리스트 대조
검색 목적 : 경쟁사의 랜섬웨어 피해 현황을 거시적으로 파악하여 사전에 대응

4. 프로젝트 키워드 기반
검색 타겟 : 텔레그램 해커 채널, 다크웹 미러링사이트(Github 포함), 실제 다크웹 사이트
검색 방식 : (선택)입력받은 키워드 + 프로젝트 키워드 (blueprint, schema, source code 등)
검색 목적 : 개발 중인 신제품, 미공개 프로젝트의 소스코드나 설계도 유출 여부 정밀 검색

사용한 기술(기술 스택)

개발 언어 : Python 3.10+
AI 엔진 : Google Gemini API
텔레그램 검색 : Telethon
동시에 여러 페이지 검색 : Aiohttp
네트워크 : Tor Expert Bundle (Port 9050)
다크웹 접속 : Requests with Tor Proxy (Socks5)
고유 id 생성 : UUID
처리 방식 : 입력된 내용 정렬 -> 다중 검색 -> json포맷으로 만듬.


환경 구성

1. Tor 네트워크 구성 (필수)

본 크롤러는 다크웹 접속을 위해 Tor 프록시가 필요합니다.
Tor Project에서 Windows Expert Bundle 다운로드(https://www.torproject.org/download/tor/)
압축 해제 후 tor.exe 실행(powershell/우클릭 후 관리자 권한으로 실행)

주의: 실행 창을 닫지 말고 백그라운드에 켜두어야 합니다.
Port: 9050 (기본 설정)

2. 라이브러리 설치

프로젝트 루트에서 다음 명령어를 실행하여 의존성 패키지를 설치합니다.

[pip install telethon aiohttp requests beautifulsoup4 python-dotenv google-generativeai]

3. 환경 변수 설정 (auth.env)

보안을 위해 API 키는 소스코드에 포함하지 않습니다. auth.env 파일을 생성하고 아래 정보를 입력하세요.

텔레그램 api(my.telegram.org 에서 발급)
telegram_api_id=11111111
telegram_api_hash=api해시값
telegram_session=deepguard_b2b_session
제미나이 api(aistudio.google.com 에서 발급)
google_api_key=구글api키

auth.env.example 파일을 참고해주시고, = 앞뒤로 공백은 없게 해주세요.

실행 방법
1. 크롤러를 실행.

2. 텔레그램 최초인증.

search_telegram 함수를 사용하기 위한 최초의 인증입니다.
최초 실행시 터미널에 출력되는 휴대폰 번호 입력 란에 입력을 하면( 01012345678이 아니라 +821012345678로 입력해주세요)
텔레그램으로 인증코드가 수신이 됩니다. 
인증코드를 입력하면 deepguard_crawl_b2b_session.session 파일이 생성이 되고,
이후에는 자동으로 로그인이 됩니다.

3. 타겟 설정(코드 내)

최하단 실행부
if __name__ == "__main__" 블록에서 진단할 대상을 설정합니다.

input_email = 
input_keyword

4. 데이터 출력

크롤러가 출력한 데이터를 통일된 json 포맷을 반환합니다. 
json 포맷은 백엔드에서 가공이 된 후 백엔드 데이터베이스 (MongoDB / Elastic Search)로 전달이 됩니다.

json

id : uuid를 통해 임의로 생성된 고유번호
keyword_type : 검색 로직(Credential, Asset, Project, Company)
source_id : 실제로 유출 내역이 검색이 된 페이지명
url : 유출이 확인된 페이지의 주소
raw_text : 내부 텍스트 전문
leak_date : 유출이 확인된 날짜.


