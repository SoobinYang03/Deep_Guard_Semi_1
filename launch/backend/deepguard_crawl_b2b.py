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
if google_api_key:
    genai.configure(api_key=google_api_key)
else:
    print("구글api키 미설정. AI 기능 제한됨.")

target_channels = [
    'cveNotify', 'jacuzzidf', 'fredenscombos', 'hannibalmaaleaks', 'lunarisS3C',
    'milkdude', 'marketo_leaks', 'leaked_databases', 'jokersworlds', 'DarkfeedNews',
    'D1rkSec', 'CrazyHuntersTeam', 'Combolistfresh', 'canyoupwnme', 'baseleeak',
    'APTANALYSIS', 'cbanke'
]

surface_header = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

surface_mirrors = {
    "pastebin": "https://pastebin.com/search/?q=",
    "Darkforums": "https://darkforums.st/search/?q=",
    "Ahmia": "https://ahmia.fi/search/?q=",
    "GitHub": "https://github.com/search?type=code&q="
}

darkweb_target = {
    "Ahmia": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q=",
    "Darkforums": "http://forums56xf3ix34sooaio4x5n275h4i7ktliy4yphhxohuemjpqovrad.onion/search.php?keywords=",
    "Torch": "http://c6txtcqza5pfilkdd65qpafpou27hfbcogb4geufxec35a4iyaxywfqd.onion/search?q="
}

threat_keywords = [
    "combo", "password", "stealer", "leak", "database", "auth", "dump",
    "fullz", "login", "hack", "email:pass", "id:pass"
]
asset_keywords = ["admin", "root", "confidential", "secret", "backup", "internal", "intranet", "vpn"]
project_keywords = ["source code", "blueprint", "schema", "design", "confidential", "internal only", "leaked", "dump",
                    "api key"]
ransomware_archive = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"

# [NEW] 가짜 데이터 필터링을 위한 제외 키워드 (블랙리스트)
SKIP_KEYWORDS = [
    "login", "signin", "sign up", "register", "terms", "privacy", "policy",
    "about", "contact", "pricing", "blog", "news", "help", "support", "status",
    "docs", "documentation", "api", "jobs", "careers", "press", "legal",
    "cookie", "sitemap", "advertisement", "subscribe", "donate"
]


def parse_company_info(email):
    try:
        domain = email.split('@')[1]
        company = domain.split('.')[0]
        return domain, company
    except:
        return None, None


def get_competitors_by_ai(company_name):
    if not google_api_key: return ["competitor_a"]
    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        prompt = (f"List top 3 major competitors of '{company_name}'. Output only names separated by comma.")
        response = model.generate_content(prompt, generation_config=genai.types.GenerationConfig(temperature=0.0))
        return [x.strip() for x in response.text.split(',')]
    except:
        return ["competitor_a"]


def add_tag(results_list, tag_name):
    for item in results_list: item['keyword_type'] = tag_name
    return results_list


# [수정] keyword_type 파라미터 추가 및 기본값 설정
def format_database(source, text, url, leak_date, target_email=None, found_keyword=None, keyword_type="credential"):
    return {
        "id": str(uuid.uuid4()),
        "keyword_type": keyword_type,  # 여기서 타입을 결정함
        "source_id": source,
        "original_link": url,
        "raw_text": text,
        "leak_date": str(leak_date),
        "target_email": target_email,
        "found_keyword": found_keyword
    }


def spamfilter(text):
    if not text or len(text) < 20: return True
    if any(k in text.lower() for k in ["join my channel", "promo code", "casino"]): return True
    return False


def get_matching_keyword(text, keyword_list):
    if not text: return None
    text_lower = text.lower()
    for k in keyword_list:
        if k in text_lower: return k
    return None


def find_any_threat_keyword(text):
    return get_matching_keyword(text, threat_keywords + asset_keywords + project_keywords)


# -------------------------------------------------------------------------
# 서피스 웹 검색
# -------------------------------------------------------------------------
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
                    text = a.get_text().strip().lower()

                    if href.startswith('/'):
                        if "github" in base_url:
                            href = f"https://github.com{href}"
                        elif "pastebin" in base_url:
                            href = f"https://pastebin.com{href}"

                    if not href.startswith('http'): continue
                    if any(bad_word in href.lower() or bad_word in text for bad_word in SKIP_KEYWORDS): continue
                    if (keyword.lower() not in href.lower()) and (keyword.lower() not in text): continue

                    links.append(href)

                for link in list(set(links))[:3]:
                    if "login" in link or "signup" in link: continue
                    detected_word = find_any_threat_keyword(link)

                    data = format_database(
                        source=f"surface({name})",
                        text=f"Detected Link: {link}",
                        url=link,
                        leak_date=datetime.now(),
                        target_email=keyword,
                        found_keyword=detected_word if detected_word else keyword,
                        keyword_type="credential"  # 기본값 설정
                    )
                    results.append(data)
    except:
        pass
    return results


async def search_surface_mirroring(keyword):
    print(f"\n미러링 및 서피스 웹 검색 시작: {keyword}")
    all_results = []
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_surface_url(session, name, url, keyword) for name, url in surface_mirrors.items()]
        results_list = await asyncio.gather(*tasks)
        for res in results_list: all_results.extend(res)
    return all_results


# -------------------------------------------------------------------------
# 다크웹 검색
# -------------------------------------------------------------------------
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
                    if '.onion' in href and 'http' in href: links.append(href)

                for link in list(set(links))[:3]:
                    try:
                        page_res = requests.get(link, headers=headers, proxies=proxies, timeout=15)
                        if keyword in page_res.text:
                            page_soup = BeautifulSoup(page_res.text, 'html.parser')
                            for s in page_soup(['script', 'style']): s.extract()
                            clean_text = ' '.join(page_soup.stripped_strings)

                            detected_word = find_any_threat_keyword(clean_text)
                            start_idx = clean_text.find(keyword)
                            start = max(0, start_idx - 50)
                            end = min(len(clean_text), start_idx + 150)
                            snippet = clean_text[start:end]

                            data = format_database(
                                source=f"darkweb ({name})",
                                text=snippet,
                                url=link,
                                leak_date=datetime.now(),
                                target_email=keyword,
                                found_keyword=detected_word if detected_word else "Darkweb Context",
                                keyword_type="credential"  # 기본값 설정
                            )
                            results.append(data)
                    except:
                        continue
        except:
            pass
    return results


# -------------------------------------------------------------------------
# 텔레그램 검색
# -------------------------------------------------------------------------
async def search_telegram(client, keyword, keyword_type):
    print(f"\n텔레그램 검색: {keyword}({keyword_type})")
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
            async for message in client.iter_messages(channel, search=keyword, limit=200):
                if spamfilter(message.text): continue
                matched_word = get_matching_keyword(message.text, check_list)
                if not matched_word: continue

                data = format_database(
                    source=f"telegram({channel})",
                    text=message.text,
                    url=f"https://t.me/{channel}/{message.id}" if 'http' not in channel else f"{channel}/{message.id}",
                    leak_date=message.date,
                    target_email=keyword,
                    found_keyword=matched_word,
                    keyword_type=keyword_type  # 검색 요청받은 타입 그대로 전달
                )
                results.append(data)
        except:
            continue
    return results


# -------------------------------------------------------------------------
# 랜섬웨어 검색
# -------------------------------------------------------------------------
def search_ransomware(target_companies):
    results = []
    try:
        res = requests.get(ransomware_archive, timeout=10)
        if res.status_code == 200:
            all_attacks = res.json()
            for attack in all_attacks:
                victim_name = str(attack.get('post_title', ''))
                for company in target_companies:
                    if re.search(r'\b' + re.escape(company) + r'\b', victim_name, re.IGNORECASE):
                        group = attack.get('group_name', 'Unknown')
                        date = attack.get('discovered', 'Unknown')
                        data = format_database(
                            source=f"ransomware({group})",
                            text=f"공격 대상: {victim_name}",
                            url=f"https://ransomlook.io/group/{group}",
                            leak_date=date,
                            target_email=None,
                            found_keyword=f"Ransomware: {group}",
                            keyword_type="asset"  # 회사 유출은 자산 위협으로 분류
                        )
                        results.append(data)
    except:
        pass
    return results


# -------------------------------------------------------------------------
# 메인 컨트롤러 (데모 모드 + 중복 제거는 Main.py에서 처리하지만 여기서도 태그는 확실히)
# -------------------------------------------------------------------------
async def main_controller(email, keyword):
    all_findings = []

    # [데모 모드] 특정 계정 검색 시 강제 결과 반환 (시연용)
    if email == "demo@deepguard.com":
        print("🚨 [Demo Mode] 데모 계정 감지 - 가짜 유출 데이터 생성")
        all_findings.append(format_database(
            source="darkweb (RaidForums)",
            text="[COMBO] Email:pass list dump... found_keyword: password matched.",
            url="http://hss33ml644n4.onion/leaks/database/123",
            leak_date=datetime.now(),
            target_email=email,
            found_keyword="password",
            keyword_type="credential"
        ))

        # 2. 기존 가짜 데이터 (Project)
        all_findings.append(format_database(
            source="surface(Pastebin)",
            text="Project Titan API Keys exposed... found_keyword: api key",
            url="https://pastebin.com/raw/k123kk",
            leak_date=datetime.now(),
            target_email=email,
            found_keyword="api key",
            keyword_type="project"
        ))

        # ---------------------------------------------------------
        # [추가됨] 3. 경쟁사/자사 랜섬웨어 피해 내역 (강제 주입)
        # ---------------------------------------------------------
        # 시연 시나리오: "DeepGuard는 AI로 경쟁사를 식별하여, 그들의 피해 사례도 함께 모니터링합니다."

        # 경쟁사 1: LG Electronics (LockBit)
        all_findings.append(format_database(
            source="ransomware(LockBit 3.0)",
            text="공격 대상: LG Electronics Service Data / Status: Published",
            url="https://ransomlook.io/group/lockbit3",
            leak_date="2024-01-15",
            target_email=None,
            found_keyword="Ransomware: LockBit",
            keyword_type="company"  # 프론트에서 색상이 다르게 보일 수 있음 (혹은 asset으로 변경)
        ))

        # 경쟁사 2: SK Hynix (BlackCat)
        all_findings.append(format_database(
            source="ransomware(ALPHV/BlackCat)",
            text="공격 대상: SK Hynix Internal Schematics / Status: Leaked",
            url="https://ransomlook.io/group/alphv",
            leak_date="2023-11-20",
            target_email=None,
            found_keyword="Ransomware: ALPHV",
            keyword_type="company"
        ))
        return all_findings

    # [실제 크롤링]
    domain, company = parse_company_info(email)
    if not domain: company = "Unknown"

    print(f"DeepGuard 진단 시작: {company} ({domain})")
    competitors = get_competitors_by_ai(company) if company != "Unknown" else []

    async with TelegramClient(tg_session, tg_api_id, tg_api_hash) as client:
        # 1. Credential
        res = await search_telegram(client, email, "credential")
        all_findings.extend(res)  # add_tag 호출 불필요 (함수 내부에서 처리함)

        res = await search_surface_mirroring(email)
        all_findings.extend(res)

        res = search_darkweb(email)
        all_findings.extend(res)

        # 2. Asset
        if domain:
            res = await search_telegram(client, domain, "asset")
            all_findings.extend(res)

        # 3. Project
        if keyword:
            res = await search_telegram(client, keyword, "project")
            for item in res:
                if not item['found_keyword']: item['found_keyword'] = "Project Leak"
            all_findings.extend(res)

            res = await search_surface_mirroring(keyword)
            # 프로젝트 검색 결과는 타입을 project로 강제 변환
            for item in res: item['keyword_type'] = "project"
            all_findings.extend(res)

        # 4. Company (Ransomware)
        if company != "Unknown":
            res = search_ransomware([company] + competitors)
            all_findings.extend(res)

    return all_findings