import requests
from bs4 import BeautifulSoup
import hashlib
import os
import time
import random
import sys
import re
import json
import platform
from PIL import Image
login_system = None
CHAR_SET = '0123456789abcdefghijklmnopqrstuvwxyz'
CAPTCHA_LEN = 4
IMG_HEIGHT, IMG_WIDTH = 50, 120

def get_account_info():
    file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '学号密码.txt')
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            line = f.readline().strip()
            if ',' in line:
                username, password = line.split(',', 1)
                return username.strip(), password.strip()
    username = input("请输入学号: ").strip()
    password = input("请输入密码: ").strip()
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(f"{username},{password}\n")
    return username, password

class SCULoginSystem:
    def __init__(self):
        self.session = requests.Session()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
            'Connection': 'keep-alive'
        }
        self.base_url = 'http://zhjw.scu.edu.cn'
        self.token_value = None

    def get_login_page(self):
        try:
            resp = self.session.get(f'{self.base_url}/login', headers=self.headers, timeout=5)
        except requests.exceptions.Timeout:
            print("获取登录页面超时，重试中...")
            return self.get_login_page()
        if resp.status_code != 200:
            print(f"获取登录页面失败，状态码: {resp.status_code}")
            return False
        soup = BeautifulSoup(resp.text, 'html.parser')
        token_input = soup.find('input', {'id': 'tokenValue'})
        if token_input:
            self.token_value = token_input.get('value')
            return True
        print("未找到token")
        return False

    def get_captcha(self):
        url = f'{self.base_url}/img/captcha.jpg'
        try:
            resp = self.session.get(url, headers=self.headers, timeout=5)
        except requests.exceptions.Timeout:
            print("获取验证码超时，重试中...")
            return self.get_captcha()
        if resp.status_code == 200:
            captcha_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'current_captcha.jpg')
            with open(captcha_path, 'wb') as f:
                f.write(resp.content)
            return captcha_path
        print(f"获取验证码失败，状态码: {resp.status_code}")
        return None

    def show_captcha(self, captcha_path):
        try:
            if platform.system() == 'Windows':
                os.startfile(captcha_path)
            elif platform.system() == 'Darwin':
                os.system(f'open "{captcha_path}"')
            else:
                os.system(f'xdg-open "{captcha_path}"')
        except Exception:
            print(f"自动打开图片失败，请手动打开: {captcha_path}")

    def encrypt_password(self, password):
        md5_1 = hashlib.md5(password.encode('utf-8')).hexdigest()
        md5_2 = hashlib.md5((password + "{Urp602019}").encode('utf-8')).hexdigest()
        return f"{md5_2}*{md5_1}"

    def login(self, username, password, max_retry=3):
        for attempt in range(1, max_retry + 1):
            if not self.get_login_page():
                print("无法获取 token。")
                return False
            captcha_path = self.get_captcha()
            if not captcha_path:
                print("获取验证码失败，重试中...")
                continue
            self.show_captcha(captcha_path)
            captcha_text = input("请输入图片中的验证码（区分大小写）：").strip()
            encrypted_password = self.encrypt_password(password)
            login_data = {
                'tokenValue': self.token_value,
                'j_username': username,
                'j_password': encrypted_password,
                'j_captcha': captcha_text
            }
            login_headers = self.headers.copy()
            login_headers.update({
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': self.base_url,
                'Referer': f'{self.base_url}/login'
            })
            try:
                resp = self.session.post(
                    f'{self.base_url}/j_spring_security_check',
                    headers=login_headers,
                    data=login_data,
                    allow_redirects=False,
                    timeout=5
                )
            except requests.exceptions.Timeout:
                print("登录请求超时，重试中...")
                time.sleep(1)
                continue
            try:
                os.remove(captcha_path)
            except Exception:
                pass
            print(f"登录尝试{attempt}，验证码：{captcha_text}，响应码：{resp.status_code}")
            if "密码错误" in resp.text or "用户密码错误" in resp.text:
                print("密码错误，请重新输入")
                return False
            if resp.status_code == 302:
                location = resp.headers.get('Location', '')
                if 'badCaptcha' in location or b'badCaptcha' in resp.content:
                    print("验证码错误，重试...")
                    time.sleep(1)
                    continue
                print("登录成功！")
                try:
                    self.session.get(f'{self.base_url}/index', headers=self.headers, timeout=5)
                except requests.exceptions.Timeout:
                    print("登录后主页加载超时，忽略。")
                return True
            print("登录失败，尝试下一个验证码...")
            time.sleep(1)
        print("多次尝试后仍未登录成功，请检查账号密码。")
        return False
    def save_cookies(self, filename='cookies.json'):
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.session.cookies.get_dict(), f)

    def load_cookies(self, filename='cookies.json'):
        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as f:
                cookies = json.load(f)
                self.session.cookies.update(cookies)
def 登录():
    global login_system
    username, password = get_account_info()
    login_system = SCULoginSystem()
    result = login_system.login(username, password)
    if result:
        print("登录成功！")
        login_system.save_cookies()
        return login_system
    else:
        print("登录失败，请检查账号密码或验证码")
        login_system = None
        return None
def 课表查询():
    global login_system
    if not login_system:
        print("请先登录教务系统！")
        return
    def print_course(course, time_place, all_units):
        course_name = course.get("courseName", "")
        course_type = course.get("courseCategoryName", "")
        course_id = f"{course['id'].get('coureNumber','')}_{course['id'].get('coureSequenceNumber','')}"
        teacher = course.get("attendClassTeacher", "")
        week_desc = time_place.get("weekDescription", "")
        location = f"{time_place.get('teachingBuildingName','')}{time_place.get('classroomName','')}"
        class_day = time_place.get("classDay", "")
        class_sessions = time_place.get("classSessions", "")
        continuing = time_place.get("continuingSession", 1)
        if class_day:
            day_str = f"周{class_day}-第{class_sessions}-{int(class_sessions)+int(continuing)-1}节"
        else:
            day_str = ""
        unit = course.get("unit", "")
        print(f"课程名：{course_name} | 类型：{course_type} | 课程号_课序号：{course_id} | 教师：{teacher}")
        print(f"上课周：{week_desc} | 位置：{location} | 上课时间：{day_str} | 学分：{unit}")
        print("-" * 60)
    def print_week_course(tp, course):
        location = f"{tp.get('teachingBuildingName','')}{tp.get('classroomName','')}"
        course_name = tp.get("coureName", "") or tp.get("courseName", "") or course.get("courseName", "")
        class_day = tp.get("classDay", "")
        class_sessions = tp.get("classSessions", "")
        continuing = tp.get("continuingSession", 1)
        teacher = tp.get("courseTeacher", "") or tp.get("attendClassTeacher", "") or course.get("attendClassTeacher", "")
        if class_day:
            day_str = f"周{class_day}-第{class_sessions}-{int(class_sessions)+int(continuing)-1}节"
        else:
            day_str = ""
        print(f"课程名：{course_name} | 上课地点：{location} | 上课时间：{day_str} | 教师：{teacher}")
        print("-" * 60)
    while True:
        print("\n请选择课表查询类型：")
        print("1. 本学期课表")
        print("2. 历年课表")
        print("3. 周课表")
        print("q. 退出")
        choice = input("请输入选项编号：").strip()
        if choice == "1":
            url = f"http://zhjw.scu.edu.cn/student/courseSelect/thisSemesterCurriculum/ajaxStudentSchedule/callback"
            resp = login_system.session.get(url, headers=login_system.headers)
            if resp.status_code == 200:
                data = resp.json()
                print(f"总学分：{data.get('allUnits','')}")
                xkxx = data.get("xkxx", [])
                for course_dict in xkxx:
                    for course in course_dict.values():
                        for tp in course.get("timeAndPlaceList", []):
                            print_course(course, tp, data.get('allUnits',''))
            else:
                print("查询失败，状态码：", resp.status_code)
        elif choice == "2":
            plan_year = input("请输入学年（如2023-2024）：").strip()
            print("请选择学期：")
            print("1. 秋季学期")
            print("2. 春季学期")
            term_c = input("请输入选项编号：").strip()
            if term_c == "1":
                plan_code = f"{plan_year}-1-1"
            elif term_c == "2":
                plan_code = f"{plan_year}-2-1"
            else:
                print("无效选项，请重新输入")
                continue
            url = f"http://zhjw.scu.edu.cn/student/courseSelect/thisSemesterCurriculum/ajaxStudentSchedule/callback"
            data = f"&planCode={plan_code}"
            resp = login_system.session.post(url, headers=login_system.headers, data=data)
            if resp.status_code == 200:
                data = resp.json()
                print(f"总学分：{data.get('allUnits','')}")
                xkxx = data.get("xkxx", [])
                for course_dict in xkxx:
                    for course in course_dict.values():
                        for tp in course.get("timeAndPlaceList", []):
                            print_course(course, tp, data.get('allUnits',''))
            else:
                print("查询失败，状态码：", resp.status_code)
        elif choice == "3":
            week = input("请输入要查询的周数（0为第0周）：").strip()
            url = f"http://zhjw.scu.edu.cn/student/courseSelect/thisSemesterCurriculum/ajaxStudentSchedule/weekLySchedule/callback/{week}"
            resp = login_system.session.get(url, headers=login_system.headers)
            if resp.status_code == 200:
                data = resp.json()
                print(f"总学分：{data.get('allUnits','')}")
                xkxx = data.get("xkxx", [])
                printed = set()
                for course_dict in xkxx:
                    for course in course_dict.values():
                        if not course.get("timeAndPlaceList"):
                            continue
                        for tp in course.get("timeAndPlaceList", []):
                            key = (tp.get("coureName","") or tp.get("courseName","") or course.get("courseName",""),
                                   tp.get("classDay",""), tp.get("classSessions",""), tp.get("teachingBuildingName",""), tp.get("classroomName",""))
                            if key in printed:
                                continue
                            printed.add(key)
                            print_week_course(tp, course)
            else:
                print("查询失败，状态码：", resp.status_code)
        elif choice == "q":
            print("已退出课表查询。")
            break
        else:
            print("无效选项，请重新输入。")

def 评教():
    global login_system
    if not login_system:
        print("请先登录教务系统！")
        return
    def print_records(records, mode):
        from colorama import init, Fore, Style
        init(autoreset=True)
        print(f"{'序号':<4}|{'课程名':<16}|{'教师/被评人':<10}|{'状态':<8}")
        print("-" * 42)
        for idx, rec in enumerate(records, 1):
            status = "已评教" if rec.get("SFPG") == "1" else f"{Fore.RED}未评教{Style.RESET_ALL}"
            if mode == "kt":
                teacher = rec.get('LSRXM', '').split(',')[0]
            else:
                teacher = rec.get('JSM', '').split(',')[0]
            print(f"{idx:<4}|{rec.get('KCM',''):<16}|{teacher:<10}|{status:<8}")
        print("-" * 42)

    options = {"1": ("期末评教", "kt"), "2": ("课堂及时评教", "ktjs")}
    url = "http://zhjw.scu.edu.cn/student/teachingAssessment/evaluation/queryAll"

    while True:
        print("\n请选择评教类型：")
        for k, v in options.items():
            print(f"{k}. {v[0]}")
        print("q. 退出")
        choice = input("请输入选项编号：").strip()
        if choice in options:
            data = {
                "pageNum": 1,
                "pageSize": 30,
                "flag": options[choice][1]
            }
            resp = login_system.session.post(url, headers=login_system.headers, data=data)
            if resp.status_code == 200:
                records = resp.json().get("data", {}).get("records", [])
                print_records(records, options[choice][1])
            else:
                print("查询失败，状态码：", resp.status_code)
        elif choice == "q":
            print("已退出评教查询")
            break
        else:
            print("无效选项，请重新输入")

def 学籍查询():
    global login_system
    if not login_system:
        print("请先登录教务系统！")
        return
    show_hidden = False
    ans = input("是否显示隐藏信息（如证件号码、通讯地址等）？(y/n): ").strip().lower()
    if ans == "y":
        show_hidden = True
    url = "http://zhjw.scu.edu.cn/student/rollManagement/rollInfo/index"
    resp = login_system.session.post(url, headers=login_system.headers)
    if resp.status_code != 200:
        print("查询失败，状态码：", resp.status_code)
        return
    soup = BeautifulSoup(resp.text, "html.parser")
    def get_real_value(value_tag):
        text = value_tag.get_text(strip=True)
        if show_hidden and text == "******":
            onclick = value_tag.get("onclick", "")
            import re
            match = re.search(r"showPlaintext\('([^']+)'", onclick)
            if match:
                return match.group(1)
        return text
    print("======== 学籍信息 ========")
    others = soup.find_all("div", class_="profile-info-row")
    for row in others:
        names = row.find_all("div", class_="profile-info-name")
        values = row.find_all("div", class_="profile-info-value")
        for name, value in zip(names, values):
            key = name.get_text(strip=True)
            val = get_real_value(value)
            if val:
                print(f"{key}: {val}")   

def clean_name(name):
    return re.sub(r"<[^>]+>", "", name).replace("&nbsp;", "").strip()
def build_tree(nodes):
    node_map = {node['id']: node for node in nodes}
    for node in nodes:
        pid = node['pId']
        if pid != "-1" and pid in node_map:
            node_map[pid].setdefault('children', []).append(node)
    return [node for node in nodes if node['pId'] == "-1"]
def print_tree(node, indent=0):
    print("  " * indent + clean_name(node['name']))
    for child in node.get('children', []):
        print_tree(child, indent + 1)
def 方案修读查询():
    global login_system
    if not login_system:
        print("请先登录教务系统！")
        return
    url = "http://zhjw.scu.edu.cn/student/integratedQuery/planCompletion/index"
    resp = login_system.session.get(url, headers=login_system.headers)
    if resp.status_code != 200:
        print("查询失败，状态码：", resp.status_code)
        return
    soup = BeautifulSoup(resp.text, "html.parser")
    print("======== 方案总体完成情况 ========")
    for box in soup.select("div#one .infobox, div#one .infobox-small"):
        num = box.select_one(".infobox-data-number")
        percent = box.select_one(".percent")
        content = box.select_one(".infobox-content")
        text = box.select_one(".infobox-text")
        if num and content:
            print(f"{content.get_text(strip=True)}: {num.get_text(strip=True)}")
        elif percent and text:
            print(f"{text.get_text(strip=True)}: {percent.get_text(strip=True)}")
        elif percent and content:
            print(f"未完成课组最低进度百分比: {percent.get_text(strip=True)}%")
        elif content:
            print(content.get_text(strip=True))
    print("======== 方案课程修读情况 ========")
    match = re.search(r'var\s+zNodes\s*=\s*(\[[\s\S]*?\]);', resp.text)
    if not match:
        print("未找到课程修读数据")
        return
    try:
        zNodes = json.loads(match.group(1).replace("\\/", "/"))
    except Exception as e:
        print("zNodes解析失败:", e)
        return
    for node in build_tree(zNodes):
        print_tree(node)
def get_score_data_url(index_url, term_type):
    global login_system
    resp = login_system.session.get(index_url, headers=login_system.headers)
    if resp.status_code != 200:
        print("获取接口地址失败，状态码：", resp.status_code)
        return None
    pattern = rf'var\s+url\s*=\s*"([^"]+/{term_type}/data)"'
    match = re.search(pattern, resp.text)
    if not match:
        print("未找到成绩数据接口地址")
        return None
    url = match.group(1)
    if url.startswith("/"):
        url = "http://zhjw.scu.edu.cn" + url
    return url

def 成绩查询():
    global login_system
    if not login_system:
        print("请先登录教务系统！")
        return
    mode = input("\n1. 历年成绩查询\n2. 本学期成绩查询\n请选择查询方式（1/2）：").strip()
    if mode == "2":
        url = get_score_data_url(
            "http://zhjw.scu.edu.cn/student/integratedQuery/scoreQuery/thisTermScores/index",
            "thisTermScores"
        )
        if not url:
            return
        resp = login_system.session.get(url, headers=login_system.headers)
        if resp.status_code != 200:
            print("查询失败，状态码：", resp.status_code)
            return
        data = resp.json()
        if not data or not isinstance(data, list):
            print("本学期暂无成绩。")
            return
        scores = data[0].get("list", [])
        if not scores:
            print("本学期暂无成绩。")
            return
        print("\n本学期成绩：")
        for item in scores:
            print(f"{item.get('courseName','')} | 分数: {item.get('courseScore','')} | 绩点: {item.get('gradePoint','')} | 等级: {item.get('levelName','')}")
    else:
        url = get_score_data_url(
            "http://zhjw.scu.edu.cn/student/integratedQuery/scoreQuery/allTermScores/index",
            "allTermScores"
        )
        if not url:
            return
        year = input("请输入学年学期（如2024-2025-2-1，回车默认本学期）：").strip() or "2024-2025-2-1"
        payload = {
            "zxjxjhh": year,
            "kch": "",
            "kcm": "",
            "pageNum": 1,
            "pageSize": 30
        }
        resp = login_system.session.post(url, headers=login_system.headers, data=payload)
        if resp.status_code != 200:
            print("查询失败，状态码：", resp.status_code)
            return
        data = resp.json()
        records = data.get("list", {}).get("records", [])
        if not records:
            print("该学期暂无成绩。")
            return
        print(f"\n{year}成绩：")
        for rec in records:
            print(f"{rec[11]} | 分数: {rec[8]} | 等级: {rec[17]}")
def parse_free_classroom(js_text: str) -> dict:
    pattern = re.compile(r"第(\d+)节.*?(?=(第\d+节|$))", re.S)
    return {
        sec_num: re.findall(r'var\s+jsm\s*=\s*"([A-Za-z0-9\u4e00-\u9fa5\-]+)"', content)
        for sec_num, _, content in (
            (m.group(1), m.group(2), m.group(0)) for m in pattern.finditer(js_text)
        )
    }

def select_option(prompt, options):
    while True:
        print(prompt)
        for idx, opt in enumerate(options, 1):
            print(f"{idx}. {opt}")
        try:
            idx = int(input("输入序号：").strip()) - 1
            if 0 <= idx < len(options):
                return idx
        except ValueError:
            pass
        print("输入有误，请重新输入。")
def 空闲教室():
    global login_system
    if not login_system:
        print("请先登录教务系统！")
        return
    resp = login_system.session.get(
        "http://zhjw.scu.edu.cn/student/teachingResources/freeClassroom/index",
        headers=login_system.headers
    )
    if resp.status_code != 200:
        print("获取校区信息失败，状态码：", resp.status_code)
        return
    xq_match = re.search(r"var\s+xqList\s*=\s*'([^']+)';", resp.text)
    bd_match = re.search(r"var\s+buildings\s*=\s*'([^']+)';", resp.text)
    if not xq_match or not bd_match:
        print("未找到校区或楼栋信息")
        return
    xq_list = json.loads(xq_match.group(1))
    buildings = json.loads(bd_match.group(1))[0]
    xq_idx = select_option("请选择校区：", [xq['campusName'] for xq in xq_list])
    campus = xq_list[xq_idx]
    campus_num = campus["campusNumber"]
    campus_name = campus["campusName"]
    bd_list = buildings[campus_num]
    bd_idx = select_option(f"\n请选择楼栋（{campus_name}）：", [bd['teachingBuildingName'] for bd in bd_list])
    building = bd_list[bd_idx]
    building_num = building["id"]["teachingBuildingNumber"]
    building_name = building["teachingBuildingName"]
    position = f"{campus_num}_{building_num}"
    print(f"\n已选择：{campus_name} - {building_name}")
    date_options = [
        ("今天", "http://zhjw.scu.edu.cn/student/teachingResources/freeClassroom/today", "post"),
        ("明天", "http://zhjw.scu.edu.cn/student/teachingResources/freeClassroomQuery/tomrrowDate", "get"),
        ("后天", "http://zhjw.scu.edu.cn/student/teachingResources/freeClassroomQuery/afTomrrowDate", "get"),
    ]
    date_idx = select_option("\n请选择查询日期：", [d[0] for d in date_options])
    url_today, url_query, method = date_options[date_idx]
    payload = {"position": position, "xqm": campus_name}
    resp_today = login_system.session.post(
        "http://zhjw.scu.edu.cn/student/teachingResources/freeClassroom/today",
        headers=login_system.headers, data=payload
    )
    if resp_today.status_code != 200:
        print("查询失败，状态码：", resp_today.status_code)
        return
    if method == "post":
        final_resp = resp_today
    else:
        final_resp = login_system.session.get(url_query, headers=login_system.headers, params=payload)
        if final_resp.status_code != 200:
            print("查询失败，状态码：", final_resp.status_code)
            return
    mode = select_option(
        "\n请选择查询方式：",
        ["概览全部空闲教室", "查询指定节次都空闲的教室（如8-9节）"]
    )
    section_map = parse_free_classroom(final_resp.text)
    if mode == 0:
        print("\n各节次空闲教室：")
        for sec_num in sorted(section_map.keys(), key=int):
            print(f"第{sec_num}节：")
            print(", ".join(section_map[sec_num]) if section_map[sec_num] else "无")
    else:
        rng = input("请输入节次范围（如8-9）：").strip()
        try:
            start, end = map(int, rng.split('-'))
        except:
            print("输入格式错误")
            return
        sets = [set(section_map.get(str(i), [])) for i in range(start, end+1)]
        if not sets or any(not s for s in sets):
            print("该节次无空闲教室")
            return
        free_rooms = set.intersection(*sets)
        print(f"\n第{start}-{end}节都空闲的教室：")
        if free_rooms:
            for room in free_rooms:
                print(f"  {room}")
        else:
            print("无")
def format_size(size):
    return f"{size/1024/1024:.2f} MB"
def download_with_progress(url, filename, session, file_id, cookie):
    headers = {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-encoding": "gzip, deflate",
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "connection": "keep-alive",
        "cookie": cookie,
        "host": "zhjw.scu.edu.cn",
        "referer": f"http://zhjw.scu.edu.cn/student/credibleReportCard/scoreCard/toPay/{file_id}",
        "upgrade-insecure-requests": "1",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0"
    }
    resp = session.get(url, headers=headers, stream=True)
    if resp.status_code != 200:
        print("下载失败，状态码：", resp.status_code)
        return False
    total = int(resp.headers.get('content-length', 0))
    script_dir = os.path.dirname(os.path.abspath(__file__))
    save_path = os.path.join(script_dir, filename)
    start_time = time.time()
    with open(save_path, "wb") as f:
        downloaded = 0
        for chunk in resp.iter_content(chunk_size=65536):
            if chunk:
                f.write(chunk)
                downloaded += len(chunk)
                if total:
                    done = int(50 * downloaded / total)
                    bar = f"\r[{'█'*done}{'.'*(50-done)}] {format_size(downloaded)}/{format_size(total)}"
                else:
                    bar = f"\r已下载 {format_size(downloaded)}"
                print(bar, end='', flush=True)
    elapsed = time.time() - start_time
    print(f"\n已保存为 {save_path}")
    print(f"下载用时：{elapsed:.2f} 秒")
    return True

def 可信证明下载():
    global login_system
    start_all = time.time()
    if not login_system:
        print("请先登录教务系统！")
        return
    resp = login_system.session.get(
        "http://zhjw.scu.edu.cn/student/integratedQuery/scoreQuery/credibleReportCard/index",
        headers=login_system.headers
    )
    soup = BeautifulSoup(resp.text, "html.parser")
    table = soup.find("table", id="resultsTable")
    proofs = []
    for tr in table.find("tbody").find_all("tr"):
        tds = tr.find_all("td")
        if len(tds) < 3:
            continue
        name = tds[1].get_text(strip=True)
        btn = tds[2].find("button")
        if not btn or "onclick" not in btn.attrs:
            continue
        m = re.search(r"askingConfirm\('([^']+)','([^']+)'\)", btn["onclick"])
        if not m:
            continue
        sqlxm, flag = m.group(1), m.group(2)
        proofs.append((name, sqlxm, flag))
    if not proofs:
        print("未找到可用的可信证明")
        return

    print("请选择要下载的可信证明：")
    for idx, (name, _, _) in enumerate(proofs, 1):
        print(f"{idx}. {name}")
    while True:
        try:
            sel = int(input("输入序号：").strip()) - 1
            if 0 <= sel < len(proofs):
                break
        except:
            pass
        print("输入有误，请重新输入。")
    name, sqlxm, flag = proofs[sel]
    resp = login_system.session.post(
        "http://zhjw.scu.edu.cn/student/integratedQuery/scoreQuery/scoreCard/ca_saveCAReportCards",
        headers=login_system.headers,
        data={"sqlxm": sqlxm, "flag": flag, "param": "", "kxlxmc": "undefined"}
    )
    try:
        result = resp.json()
    except Exception:
        print("返回内容解析失败")
        return
    if "id" not in result:
        print("生成失败，返回信息：", result.get("flag", "未知错误"))
        return
    file_id = result["id"]
    url_download = f"http://zhjw.scu.edu.cn/student/integratedQuery/scoreQuery/scoreCard/courseInfo/ca_previewOrDownloadCard/{file_id}"
    filename = f"{name}.pdf"
    cookie_str = "; ".join([f"{k}={v}" for k, v in login_system.session.cookies.get_dict().items()])
    download_with_progress(url_download, filename, login_system.session, file_id, cookie_str)
    print(f"总用时：{time.time()-start_all:.2f} 秒")
def 刷新():
    global login_system
    if not login_system:
        print("请先登录教务系统！")
        return
    print("刷新中...")
    try:
        res = login_system.session.get("http://zhjw.scu.edu.cn/index", headers=login_system.headers, timeout=5)
        if res.status_code != 200:
            print(f"刷新失败，状态码: {res.status_code}")
            return
        else:
            print("刷新成功！")
            print(res.text)
    except requests.exceptions.Timeout:
        print("刷新超时，请稍后再试。")
def display_menu():
    title = "《教务系统》"
    print(f"\033[1;36m{title.center(30)}\033[0m")
    print("=" * 30)
    menu_items = {
        "0": "登录教务系统",
        "1": "课表查询",
        "2": "评教(下次评教更新)",
        "3": "学籍查询",
        "4": "方案修读查询",
        "5": "成绩查询",
        "6": "空闲教室",
        "7": "可信证明下载",
        "8": "自动选课(补退选更新)",
        "9": "考试安排(下次考试更新)",
        "q": "退出程序"
    }
    LEFT_WIDTH = 20  
    def display_width(s):
        width = 0
        for char in s:
            if '\u4e00' <= char <= '\u9fff':  
                width += 2
            else:
                width += 1
        return width
    def ljust_visual(s, width):
        current_width = display_width(s)
        if current_width >= width:
            return s
        padding = ' ' * (width - current_width)
        return s + padding
    item_0_prefix = " 0: "
    item_0 = f"{item_0_prefix}{menu_items['0']}"
    print(item_0)
    other_keys = [k for k in menu_items.keys() if k != "0"]
    other_keys.sort(key=lambda x: int(x) if x.isdigit() else float('inf'))
    for i in range(0, len(other_keys), 2):
        left_key = other_keys[i]
        left_text = menu_items[left_key]
        if len(left_key) == 1:
            left_prefix = f" {left_key}: "
        else:
            left_prefix = f" {left_key}:"
        left_full = f"{left_prefix}{left_text}"
        left_formatted = ljust_visual(left_full, LEFT_WIDTH)
        if i + 1 < len(other_keys):
            right_key = other_keys[i + 1]
            right_text = menu_items[right_key]
            if len(right_key) == 1:
                right_prefix = f" {right_key}: "
            else:
                right_prefix = f" {right_key}:"
            right_full = f"{right_prefix}{right_text}"
            print(f"{left_formatted}{right_full}")
        else:
            print(left_formatted)
    print("=" * 60)
    
    print("请选择:")
def call_functions(choices):
    for choice in choices:
        if choice == "1":
            课表查询()
        elif choice == "2":
            评教()
        elif choice == "3":
            学籍查询()
        elif choice == "4":
            方案修读查询()
        elif choice == "5":
            成绩查询()
        elif choice == "6":
            空闲教室()
        elif choice == "7":
            可信证明下载()
        elif choice == "8":
            刷新()
        elif choice == "0":
            登录()
        elif choice == 'q':
            print("退出程序")
            return False
    return True
def cookies():
    global login_system
    login_system = SCULoginSystem()
    if os.path.exists('cookies.json'):
        login_system.load_cookies('cookies.json')
        print("刷新登录状态...")
        try:
            res = login_system.session.get("http://zhjw.scu.edu.cn/index", headers=login_system.headers, timeout=5)
            if res.status_code == 200:
                print("登录状态未过期，无需登录")
                return True
            else:
                print(f"cookies已过期，响应状态码：{res.status_code}")
                print(res.text)
                login_system = None
                return False
        except Exception as e:
            print("刷新异常：", e)
            login_system = None
            return False
    else:
        print("未检测到cookies文件，请先登录")
        return False
def main():
    while True:
        display_menu()
        choices = input("请输入选项编号(必须先输入0登录):").split()
        if 'q' in choices:
            break
        filtered_choices = [c for c in choices if c != 'q']
        if call_functions(filtered_choices):
            print("请再次选择。")
if __name__ == "__main__":
    if not cookies():
        登录()
    main()
