import requests
from bs4 import BeautifulSoup
import re
import asyncio
from telethon import TelegramClient
from urllib.parse import quote
import uuid
from datetime import datetime
import os
from dotenv import load_dotenv
import aiohttp
import google.generativeai as genai

load_dotenv(dotenv_path='auth.env')

# [설정 부분]
tor_port = 9050
tor_proxy = f"socks5h://127.0.0.1:{tor_port}"
proxies = {'http': tor_proxy, 'https': tor_proxy}
headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/91.0'}

tg_api_id = int(os.getenv('telegram_api_id'))
tg_api_hash = os.getenv('telegram_api_hash')
tg_session = os.getenv('telegram_session')

google_api_key = os.getenv('google_api_key')
if google_api_key :
    genai.configure(api_key=google_api_key)
else :
    print("구글api키 미설정. get_competitors_by_ai 함수의 사용이 제한됩니다.")

target_channels = [
    'cveNotify', 'jacuzzidf',
    'fredenscombos', 'hannibalmaaleaks', 'lunarisS3C', 'milkdude',
    'marketo_leaks', 'leaked_databases', 'jokersworlds', 'DarkfeedNews',
    'D1rkSec', 'CrazyHuntersTeam', 'Combolistfresh', 'canyoupwnme',
    'baseleeak', 'APTANALYSIS', 'cbanke',
]

surface_header = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

surface_mirrors = {
    "pastebin" : "https://pastebin.com/search/?q=",
    "Darkforums" : "https://darkforums.st/search/?q=",
    "Ahmia" : "https://ahmia.fi/search/?q=",
    "GitHub" : "https://github.com/search?type=code&q="
}

darkweb_target = {
    "Ahmia": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q=",
    #"Haystack": "http://haystak5njsmn2hqkewiiqyt7znwvevgqnua56jqgsw52db632e226ad.onion/?q=",
    "Darkforums": "http://forums56xf3ix34sooaio4x5n275h4i7ktliy4yphhxohuemjpqovrad.onion/search.php?keywords=",
    "Torch": "http://c6txtcqza5pfilkdd65qpafpou27hfbcogb4geufxec35a4iyaxywfqd.onion/search?q="
}

threat_keywords = [
    "combo", "password", "stealer", "leak", "database", "auth", "dump",
    "fullz", "login", "hack", "email:pass", "id:pass"
]
asset_keywords = [
    "admin", "root", "confidential", "secret", "backup", "internal", "intranet", "vpn"
]

project_keywords = [
    "source code", "blueprint", "schema", "design", "confidential", "internal only", "leaked", "dump", "api key"
]

ransomware_archive = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"

#입력한 이메일주소 파싱
def parse_company_info(email):
    try:
        domain = email.split('@')[1]
        company = domain.split('.')[0]
        return domain, company
    except:
        return None, None

#AI를 기반으로 경쟁사 목록 추출(임시)
def get_competitors_by_ai(company_name):
    print(f"\nAI로 '{company_name}'의 경쟁사의 이름을 가져옴.")

    if not google_api_key:
        print("API키가 없으므로 임시DB 사용")

    else:
        try:
            model = genai.GenerativeModel('gemini-2.5-flash')
            prompt = (
                f"List top 3 major competitors of '{company_name}'. "
                f"Strictly output ONLY the company names separated by a comma. "
                f"Do not write any sentences, numbers, bullet points, or explanations. "
                f"Example output: 'Apple, LG, Xiaomi'"
            )
            response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(temperature=0.0)
            )

            clean_text = response.text.replace('\n', '').strip()
            competitors = [x.strip() for x in response.text.split(',')]
            print(f"경쟁사명: {competitors}")
            return competitors

        except Exception as e:
            print(f"AI 호출 오류 {e}")
            print(f"호출 오류로 인해 임시 DB를 사용합니다.")
    #오류가 생기면 일단 임시DB를 사용.
    mock_db = {
        "samsung": ["lg", "apple", "sk_hynix"],
        "naver": ["kakao", "google", "meta"],
    }
    return mock_db.get(company_name.lower(), ["competitor_a"])

def add_tag(results_list, tag_name):
    for item in results_list:
        item['keyword_type'] = tag_name
    return results_list

#데이터포맷팅 json생성
def format_database(source, text, url, leak_date):
    return {
        "id": str(uuid.uuid4()),
        "keyword_type": None,
        "source_id": source,
        "original_link": url,
        "raw_text": text,
        "leak_date": str(leak_date)
    }

#광고가 포함된 키워드는 삭제
def spamfilter(text):
    if not text:
        return True

    if len(text) < 20:
        return True

    spam_keywords = [
        "join my channel", "promo code", "discount", "bitcoin",
        "crypto investment", "hot girls", "casino"
    ]
    if any(keyword in text.lower() for keyword in spam_keywords):
        return True

    return False

#rawtext를 추출하는 함수
def extract_context(full_text, keyword):
    try:
        match = re.search(re.escape(keyword), full_text, re.IGNORECASE)
        if match:
            start = max(0, match.start() - 100)
            end = min(len(full_text), match.end() + 100)
            return full_text[start:end].replace('\n', ' ').strip()
    except:
        pass
    return full_text[:100].replace('\n', ' ').strip()

#입력한 이메일과 키워드가 둘 다 있어야 유출로 인식.
def valid_check(text, keyword_list):
    if not text:
        return False
    text_lower = text.lower()

    if any(k in text_lower for k in keyword_list):
        return True

    return False

#텔레그램에서 검색함수
async def search_telegram(client, keyword, keyword_type):
    print(f"\n텔레그램 검색 시작: {keyword}({keyword_type})")
    results = []

    if keyword_type == "credential":
        check_list = threat_keywords
    elif keyword_type == "asset":
        check_list = asset_keywords
    elif keyword_type == "project":
        check_list = project_keywords
    else:
        check_list = []

    for channel in target_channels:
        try:
            hit_count = 0

            async for message in client.iter_messages(channel, search=keyword, limit=200):
                if spamfilter(message.text):
                    continue
                if not valid_check(message.text, check_list):
                    continue

                data = format_database(
                    source=f"telegram({channel})",
                    text=message.text,
                    url=f"https://t.me/{channel}/{message.id}" if 'http' not in channel else f"{channel}/{message.id}",
                    leak_date=message.date
                )
                results.append(data)
                hit_count += 1

            if hit_count > 0:
                print(f"[{channel}] 총 {hit_count}건의 유출 발견.")

        except Exception as e:
            print(f" 오류. {channel}: {e}")
            continue
    return results

#서피스웹 검색(미러링사이트,github)
async def fetch_surface_url(session, name, base_url, keyword):

    search_url = f"{base_url}{quote(keyword)}"
    results = []

    try:
        async with session.get(search_url, headers=surface_header, timeout=50) as response:
            if response.status == 200:
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                links = []

                for a in soup.find_all('a', href=True):
                    href = a['href']
                    if 'http' in href: links.append(href)
                    elif href.startswith('/') and "github" in base_url: links.append(f"https://github.com{href}")

                for link in list(set(links))[:3]:
                    if "login" in link or "signup" in link: continue
                    data = format_database(
                        source=f"surface({name})",
                        text=f"link:{link}",
                        url=link,
                        leak_date=datetime.now()
                    )
                    results.append(data)
    except: pass
    return results

async def search_surface_mirroring(keyword):
    print(f"\n미러링 및 서피스 웹 검색 시작: {keyword}")
    all_results = []

    async with aiohttp.ClientSession() as session:
        tasks = [fetch_surface_url(session, name, url, keyword) for name, url in surface_mirrors.items()]
        results_list = await asyncio.gather(*tasks)

        for res in results_list: all_results.extend(res)

    return all_results

#다크웹을 검색
def search_darkweb(keyword):
    print(f"\n다크웹 검색 시작: {keyword}")
    results = []

    for name, base_url in darkweb_target.items():
        search_url = f"{base_url}{quote(keyword)}"

        try:
            res = requests.get(search_url, headers=headers, proxies=proxies, timeout=60)

            if res.status_code == 200:
                soup = BeautifulSoup(res.text, 'html.parser')
                links = []

                for a in soup.find_all('a', href=True):
                    href = a['href']
                    if '.onion' in href and 'http' in href:
                        links.append(href)

                links = list(set(links))[:3]

                found_count = 0
                for link in links:
                    try:
                        page_res = requests.get(link, headers=headers, proxies=proxies, timeout=15)

                        if keyword in page_res.text:

                            page_soup = BeautifulSoup(page_res.text, 'html.parser')

                            for script in page_soup(['script', 'style', 'head', 'meta', 'noscript']):
                                script.extract()
                            clean_text = ' '.join(page_soup.stripped_strings)
                            real_context = ""

                            if keyword in clean_text:
                                real_context = extract_context(clean_text, keyword)

                            else:
                                found_in_link = False
                                for a in page_soup.find_all('a', href=True):
                                    if keyword in a['href']:
                                        real_context= f"링크 발견: {a['href']}"
                                        found_in_link = True
                                        break

                                if not found_in_link:
                                    real_context = "HTML 소스코드에서 발견(숨겨진 메타데이터 또는 속성)"

                            data = format_database(
                                source=f"darkweb ({name})",
                                text=real_context,
                                url=link,
                                leak_date=datetime.now()
                            )
                            results.append(data)
                            found_count += 1
                    except:
                        continue

                if found_count > 0:
                    print(f"[{name}] 총 {found_count}건의 유출 발견.")

        except Exception as e:
            print(f"[{name}] 접속 실패 (Tor 연결 확인 필요)")

    return results

#회사명 기반 랜섬웨어 검색
def search_ransomware(target_companies):
    print(f"\n랜섬웨어 위협 정보 검색 (대상: {target_companies})")
    results = []

    try:
        res = requests.get(ransomware_archive, timeout=10)
        if res.status_code == 200:
            all_attacks = res.json()

            for attack in all_attacks:
                victim_name = str(attack.get('post_title', ''))

                for company in target_companies:
                    pattern = r'\b' + re.escape(company) + r'\b'

                    if re.search(pattern, victim_name, re.IGNORECASE):
                        group_name = attack.get('group_name', 'Unknown')
                        date = attack.get('discovered', 'Unknown')

                        raw_text = f"공격 대상: {attack.get('post_title')} / 회사명: {group_name} / 일자: {date}"

                        data = format_database(
                            source=f"ransomware({group_name})",
                            text=raw_text,
                            url=f"https://ransomlook.io/group/{group_name}",
                            leak_date=date
                        )
                        results.append(data)
                        print(f"{company.lower()} 관련 랜섬웨어 피해 정보 발견 (공격자: {group_name})")
        else:
            print("랜섬웨어 피드 접속 실패")

    except Exception as e:
        print(f"랜섬웨어 조회 중 오류: {e}")

    return results

#컨트롤러
async def main_controller(email_list, keyword=None):
    all_findings = []

    #중복된 내용은 제거
    deduplicate_domains = set()
    deduplicate_companies = set()

    if isinstance(email_list, str):
        email_list = [email_list]

    email_mapping = {}

    #데이터 1차 가공.(이메일주소, 중복도메인 제거, 중복회사명 제거)
    for email in email_list:
        domain, company = parse_company_info(email)
        if domain and company:
            deduplicate_domains.add(domain)
            deduplicate_companies.add(company)
            email_mapping[email] = {'domain' : domain, 'company' : company}

    #태그 붙여서 데이터 포맷에 추가
    def add_tag(results_list, tag_name):
        for item in results_list:
            item['keyword_type'] = tag_name
        return results_list

    print(">>> 텔레그램 세션 연결 중")
    async with TelegramClient(tg_session, tg_api_id, tg_api_hash) as client:

        print(f"[Layer 1] 이메일 기반 유출 분석 {len(email_list)}회")
        for email in email_list: 
            res = await search_telegram(client, email, "credential")
            all_findings.extend(add_tag(res, "credential"))

            res = await search_surface_mirroring(email)
            all_findings.extend(add_tag(res, "credential"))

            res = search_darkweb(email)
            all_findings.extend(add_tag(res, "credential"))

        print(f"[Layer 2] 도메인 기반 유출 분석 {len(deduplicate_domains)}회")
        for domain in deduplicate_domains: 
            res = await search_telegram(client, domain, "asset") 
            all_findings.extend(add_tag(res, "asset"))

            res = await search_surface_mirroring(domain)
            all_findings.extend(add_tag(res, "asset"))

            res = search_darkweb(domain)
            all_findings.extend(add_tag(res, "asset"))

        print(f"[Layer 3] 회사명 기반 랜섬웨어 분석 {len(deduplicate_companies)}회")
        for company in deduplicate_companies:
            competitors = get_competitors_by_ai(company)
            ransomware_targets = [company] + competitors
            
            res = search_ransomware(ransomware_targets)
            all_findings.extend(add_tag(res, "company"))

        if keyword:
            print(f"[Layer 4] 프로젝트 키워드 분석: {keyword}")

            res = await search_telegram(client, keyword, "project")
            all_findings.extend(add_tag(res, "project"))

            res = await search_surface_mirroring(keyword)
            all_findings.extend(add_tag(res, "project"))

            res = search_darkweb(keyword)
            all_findings.extend(add_tag(res, "project"))

    return all_findings

# 실행부
if __name__ == "__main__":
    input_email = [
        "buygame@g2a.com"
    ]
    input_keyword = "galaxy"

    try:
        final_results = asyncio.run(main_controller(input_email, input_keyword))

        print("\n검사 결과")
        if not final_results:
            print("발견된 유출 내역이 없습니다.")
        else:
            for item in final_results:
                tag = item.get('keyword_type', 'unknown')
                src = item.get('source_id', 'unknown')
                txt = item.get('text', '')

                print(f"[{item['keyword_type']}][{item['source_id']}] {item['raw_text'][:100]}...")
                print("-"*10)

    except Exception as e:
        print(f"오류 발생: {e}")

