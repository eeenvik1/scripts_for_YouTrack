#! /usr/bin/python3
import time

import jinja2
import requests
from bs4 import BeautifulSoup
import urllib3
from cpe import CPE
import nvdlib
import ast
import re
import smtplib
from email.message import EmailMessage
from dotenv import dotenv_values
import os
import random
from stickers import stickers
from usage import pattern, template

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
config = dotenv_values(dotenv_path)
# imported variables from .env
YOU_TRACK_TOKEN = config.get("YOU_TRACK_TOKEN")
YOU_TRACK_PROJECT_ID = config.get("YOU_TRACK_PROJECT_ID")
YOU_TRACK_BASE_URL = config.get("YOU_TRACK_BASE_URL")
URL_GET_PRODUCTS = config.get("URL_GET_PRODUCTS")
URL_GET_VERSIONS = config.get("URL_GET_VERSIONS")
EMAIL_HOST = config.get("EMAIL_HOST")
EMAIL_PORT = config.get("EMAIL_PORT")
EMAIL_HOST_PASSWORD = config.get("EMAIL_HOST_PASSWORD")
EMAIL_HOST_USER = config.get("EMAIL_HOST_USER")
USER1 = config.get("USER1")
USER2 = config.get("USER2")
MAIN_URL_OPENCVE = config.get("MAIN_URL_OPENCVE")
USERNAME = config.get("USERNAME_OPENCVE")
PASSWORD = config.get("PASSWORD_OPENCVE")
BOT_TOKEN = config.get("BOT_TOKEN")
CHAT_ID_J = config.get("CHAT_ID_J")
CHAT_ID_R = config.get("CHAT_ID_R")
CHAT_ID_A = config.get("CHAT_ID_A")


URL = str(YOU_TRACK_BASE_URL) + "/issues"


# check https://github.com/nu11secur1ty/ -------------------------------------------------------------------------------
def get_exploit_info(cve):
    link = 'https://github.com/nu11secur1ty/CVE-mitre'
    link_2 = 'https://github.com/nu11secur1ty/CVE-mitre/tree/main/2022'
    default_link = ''
    poc_cve_list = []
    r = requests.get(link)
    soup = BeautifulSoup(r.text, "html.parser")
    for cve_id in soup.find_all("span", class_="css-truncate css-truncate-target d-block width-fit"):
        regex = re.findall(r'CVE-\d{4}-\d{4,8}', cve_id.text)
        if regex:
            poc_cve_list.append(str(regex[0]))

    r = requests.get(link_2)
    soup = BeautifulSoup(r.text, "html.parser")
    for cve_id in soup.find_all("span", class_="css-truncate css-truncate-target d-block width-fit"):
        regex = re.findall(r'CVE-\d{4}-\d{4,8}', cve_id.text)
        if regex:
            poc_cve_list.append(str(regex[0]))

    for item in poc_cve_list:
        if cve == item:
            default_link = f'https://github.com/nu11secur1ty/CVE-mitre/tree/main/{cve}'
    return default_link


# check https://github.com/trickest/cve/ -------------------------------------------------------------------------------
def get_exploit_info_2(cve):
    # print('get_exploit_info_2') # DEBUG
    year = cve.split('-')[1]
    link = f'https://github.com/trickest/cve/tree/main/{year}'
    r = requests.get(link)
    soup = BeautifulSoup(r.text, "html.parser")
    default_link = ''
    for cve_id in soup.find_all("span", class_="css-truncate css-truncate-target d-block width-fit"):
        if f'{cve}.md' == cve_id.text:
            default_link = f'**trickest/cve** - https://github.com/trickest/cve/tree/main/{year}/{cve}.md'
            break
    return default_link


# parse opencve.io------------------------------------------------------------------------------------------------------
def parsing_opencve():
    url1 = 'https://www.opencve.io/login/'
    url2 = 'https://www.opencve.io/login'
    csrf_token = ''
    s = requests.Session()
    response = s.get(url1)
    soup = BeautifulSoup(response.text, 'lxml')

    # Get CSRF
    for a in soup.find_all('meta'):
        if 'name' in a.attrs:
            if a.attrs['name'] == 'csrf-token':
                csrf_token = a.attrs['content']

    # Authentication
    s.post(
        url2,
        data={
            'username': USERNAME,
            'password': PASSWORD,
            'csrf_token': csrf_token,
        },
        headers={'referer': 'https://www.opencve.io/login'},
        verify=False
    )
    # Get new CVE
    cve_line = []
    for page_num in range(1, 20):
        pagination = f'https://www.opencve.io/?page={page_num}'
        resp = s.get(pagination)
        parse = BeautifulSoup(resp.text, 'lxml')
        for cve in parse.find_all('h3', class_='timeline-header'):
            index = cve.text.find('has changed')
            if index == -1:
                cve_line.append(cve.text.replace(' is a new CVE', ''))

    cve_line_no_replic = []
    for item in cve_line:
        if item not in cve_line_no_replic:
            cve_line_no_replic.append(item[:-1])
    return cve_line_no_replic


# main function for upload information on YT----------------------------------------------------------------------------
def get_cve_data(cve):
    r = nvdlib.getCVE(cve, cpe_dict=False)
    cve_cpe_nodes = r.configurations.nodes
    cpe_nodes = ast.literal_eval(str(r.configurations))
    try:
        score = r.v3score
        vector = r.v3vector
    except:
        score = 0.1
        vector = "Нет: cvss vector"

    if vector != "Нет: cvss vector":
        vector = r.v3vector[9:len(r.v3vector)]

    links = []
    exploit_links = []
    links.append(r.url)
    for t in r.cve.references.reference_data:
        links.append(t.url)
        if 'Exploit' in t.tags:
            exploit_links.append(t.url)

    if get_exploit_info(cve):  # check https://github.com/nu11secur1ty/
        exploit_links.append(get_exploit_info(cve))
    if get_exploit_info_2(cve):  # check https://github.com/trickest/cve/
        exploit_links.append(get_exploit_info_2(cve))

    cpe_for_product_vendors = []
    if cpe_nodes:
        for conf in cve_cpe_nodes:
            if conf.operator == 'AND':
                children = [conf.children[0]]
            else:
                children = [conf]
            for child in children:
                for cpe in child.cpe_match:
                    cpe_for_product_vendors.append(cpe.cpe23Uri)

# parse CPE-------------------------------------------------------------------------------------------------------------
    product_vendor_list = []
    product_image_list = []
    version_list = []
    for cpe in cpe_for_product_vendors:
        cpe_parsed = CPE(cpe)
        product = cpe_parsed.get_product()
        vendor = cpe_parsed.get_vendor()
        product_vendor = vendor[0] + " " + product[0] if product != vendor else product[0]
        product_vendor_list.append(product_vendor)
        product_image_list.append(product[0])
        version = cpe_parsed.get_version()
        if version[0] != '-' and version[0] != '*':
            version_list.append(f'{product[0]} - {version[0]}')

    temp1 = []
    for item in version_list:
        if item not in temp1:
            temp1.append(item)
    versions = []
    for item in temp1:
        ver = {"name": item}
        versions.append(ver)

    prod = []
    for item in product_image_list:
        if item not in prod:
            prod.append(item)

    content = []
    for item in product_vendor_list:
        con = {"name": item}
        content.append(con)

    value = "Да"
    if not exploit_links:
        value = "Нет"

# check regex in cve----------------------------------------------------------------------------------------------------
    cve_name = ''
    cve_info = r.cve.description.description_data[0].value
    for item in pattern:
        if item.upper() in cve_info.upper():
            cve_name = cve + " - " + item
            break
        else:
            cve_name = cve

# message---------------------------------------------------------------------------------------------------------------
    data = {
        'cve': cve_info,
        'lastModifiedDate': r.lastModifiedDate[:-7],
        'publishedDate': r.publishedDate[:-7],
        'configurations': cpe_nodes,
        'score': score,
        'vector': r.v3vector,
        'links': links,
        'product_vendor_list': prod,
        'exploit_links': exploit_links
    }
    message = jinja2.Template(template).render(d=data)

# check for product_vendor----------------------------------------------------------------------------------------------
    headers = {
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(YOU_TRACK_TOKEN),
        "Content-Type": "application/json"
    }
    data_prod = requests.get(URL_GET_PRODUCTS, headers=headers).json()

    upload_prod = []
    for buff in product_vendor_list:
        upload_prod.append(buff)

    prod_vend = []
    for i in data_prod:
        prod_vend.append(i['name'])

    temp = []
    for iter in upload_prod:
        if iter not in prod_vend:
            temp.append(iter)

    for upload in temp:
        payload = {
            "id": "0",
            "&type": "FieldStyle",
            "name": upload
        }
        requests.post(URL_GET_PRODUCTS, headers=headers, json=payload)

# check for versions----------------------------------------------------------------------------------------------------
    headers = {
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(YOU_TRACK_TOKEN),
        "Content-Type": "application/json"
    }
    data_ver = requests.get(URL_GET_VERSIONS, headers=headers).json()

    ver_list = []
    for i in data_ver:
        ver_list.append(i['name'])

    temp2 = []
    for iter in temp1:
        if iter not in ver_list:
            temp2.append(iter)

    for upload in temp2:
        payload = {
            "id": "0",
            "&type": "FieldStyle",
            "name": upload
        }
        requests.post(URL_GET_VERSIONS, headers=headers, json=payload)

# upload information on cve---------------------------------------------------------------------------------------------
    buff_content = []
    buff_versions = []
    check_mark = '✓'  # easter_egg or bug (ya xz)
    if re.search(r'windows', str(product_vendor_list[0])):
        con = {"name": "Microsoft Windows"}
        buff_content.append(con)
        buff_versions = versions
    elif re.search(r'juniper', str(product_vendor_list[0])):
        con = {"name": "Juniper"}
        buff_content.append(con)
        buff_versions = versions
    elif re.search(r'adaptive_security_appliance', str(product_vendor_list[0])):
        con = {"name": "Cisco ASA"}
        buff_content.append(con)
        buff_versions = versions
    else:
        if content:
            buff_content.append(content[0])
        if versions:
            buff_versions.append(versions[0])

    priority = ''
    if isinstance(score, float):
        if 0.1 <= score <= 3.9:
            priority = 'Низкая'
        elif 4.0 <= score <= 6.9:
            priority = 'Средняя'
        elif 7.0 <= score <= 8.9:
            priority = 'Высокая'
        elif 9.0 <= score <= 10.0:
            priority = 'Критическая'

    request_payload = {
        "project": {
            "id": YOU_TRACK_PROJECT_ID
        },
        "summary": cve_name,
        "description": message,
        "tags": [
            {
                "name": "OpenCVE",
                "id": "6-20",
                "$type": "IssueTag"
            }
        ],
        "customFields": [
            {
                "name": "Продукт (пакет)",
                "$type": "MultiEnumIssueCustomField",
                "value": buff_content
            },
            {
                "name": "Есть эксплоит",
                "$type": "SingleEnumIssueCustomField",
                "value": {"name": value}
            },
            {
                "name": "Affected versions",
                "$type": "MultiEnumIssueCustomField",
                "value": buff_versions
            },
            {
                "name": "CVSS Score",
                "$type": "SimpleIssueCustomField",
                "value": score

            },
            {
                "name": "CVSS Vector",
                "$type": "SimpleIssueCustomField",
                "value": str(vector)

            },
            {
                "name": "Priority",
                "$type": "SingleEnumIssueCustomField",
                "value": {"name": priority}
            },
        ]
    }
    # print(request_payload)  #Debug
    post = requests.post(URL, headers=headers, json=request_payload)   # Выгрузка информации о cve в YouTrack
    return post.status_code


def email_alert(cve_list):
    recipients = []
    recipients.append(USER1)
    recipients.append(USER2)
    msg = EmailMessage()
    msg['Subject'] = 'OpenCVE'
    msg['From'] = EMAIL_HOST_USER
    msg['To'] = ", ".join(recipients)
    if len(cve_list) == 1:
        body = f'Добавлена информация о новой уязвимости {cve_list[0]}'
    else:
        body = f'Добавлена информация о новых уязвимостях\n {", ".join(cve_list)}'
    msg.set_content(body)
    msg.set_content(body)
    smtp_server = smtplib.SMTP_SSL(host=EMAIL_HOST, port=EMAIL_PORT)
    smtp_server.login(user=EMAIL_HOST_USER, password=EMAIL_HOST_PASSWORD)
    smtp_server.send_message(msg)
    print('Email sent {}'.format(msg['Subject']))


# alert on telegram bot---------------------Использовать на свой страх и риск-------------------------------------------
def telegram_alert(message):
    sticker = random.choice(stickers)
    sticker = random.choice(stickers)
    # R Alert
    requests.get(
        f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage?chat_id={CHAT_ID_R}&text={message}&parse_mode=markdown")
    requests.get(f"https://api.telegram.org/bot{BOT_TOKEN}/"f"sendSticker?chat_id={CHAT_ID_R}&sticker={sticker}")
    # Dj Alert
    requests.get(
        f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage?chat_id={CHAT_ID_J}&text={message}&parse_mode=markdown")
    requests.get(f"https://api.telegram.org/bot{BOT_TOKEN}/sendSticker?chat_id={CHAT_ID_J}&sticker={sticker}")
    # A Alert
    requests.get(
        f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage?chat_id={CHAT_ID_A}&text={message}&parse_mode=markdown")
    requests.get(f"https://api.telegram.org/bot{BOT_TOKEN}/sendSticker?chat_id={CHAT_ID_A}&sticker={sticker}")


# -------------------------------------------------MAIN-----------------------------------------------------------------
headers = {
    "Accept": "application/json",
    "Authorization": "Bearer {}".format(YOU_TRACK_TOKEN),
    "Content-Type": "application/json"
}
list_summary = requests.get(MAIN_URL_OPENCVE, headers=headers).json()  # Получение задач с YouTrack
cve_line = parsing_opencve()  # Получение списка новых cve с сайта opencve.io

sum_list = []
for n, item in enumerate(list_summary):  # Получение описания для каждой уязвимости
    regex = re.search(r'CVE-\d{4}-\d{4,8}', list_summary[n]['summary'])
    if regex:
        sum_list.append(str(regex.group()))

vuln_list = []
for item in cve_line:  # Удаление идентификаторов CVE по которым уже заведены задачи
    if item not in sum_list:
        vuln_list.append(item)

cve_list = []
for i, item in enumerate(vuln_list):  # Заведение задач в YouTrack
    time.sleep(10)
    cve = vuln_list[i]
    post = get_cve_data(cve)
    if post == 200:
        cve_list.append(cve)
    print(f'{i + 1} / {len(vuln_list)} - {post}')


cve_list_new = []
if cve_list:
    for item in cve_list:
        cve_list_new.append(f'[{item}](https://nvd.nist.gov/vuln/detail/{item})')

# telegram alert
if cve_list_new:
    if len(cve_list_new) == 1:
        message = f'*OPENCVE*\nДобавлена информация о новой уязвимости {cve_list_new[0]}'
        telegram_alert(message)
    else:
        message = f'*OPENCVE*\nДобавлена информация о новых уязвимостях {", ".join(cve_list_new)}'
        telegram_alert(message)

