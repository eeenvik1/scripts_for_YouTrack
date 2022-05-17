import json
import PyPDF2
import os.path
import os
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
import random
from stickers import stickers

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
config = dotenv_values(dotenv_path)
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
MAIN_URL_PDF = config.get("MAIN_URL_PDF")
BOT_TOKEN = config.get("BOT_TOKEN")
CHAT_ID_J = config.get("CHAT_ID_J")
CHAT_ID_R = config.get("CHAT_ID_R")

URL = str(YOU_TRACK_BASE_URL) + "/issues"
PATH = os.path.join(os.path.dirname(__file__), 'bulletins')


# parse github/nu11secur1ty------------------------------------------------------------------------------------------
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


# parse bulletine NKCKI------------------------------------------------------------------------------------------------
def get_cve_list(name_list):
    cve_list = []
    cve_list_repeat = []
    for name in name_list:
        pdf_file = open(f'{PATH}/{name}', 'rb')
        read_pdf = PyPDF2.PdfFileReader(pdf_file)
        number_of_pages = read_pdf.getNumPages()
        data = ''
        for i in range(number_of_pages):
            page = read_pdf.getPage(i)
            page_content = page.extractText()
            data1 = json.dumps(page_content)
            data += data1

        rez = ''
        for n, item in enumerate(data, start=0):
            if item != '\\':
                rez += data[n]

        result = ''
        for n, item in enumerate(rez, start=0):
            if item != 'n':
                result += rez[n]
        rez1 = result.replace(" ", "")

        regex = re.findall(r'CVE-\d{4}-\d{4,8}', rez1)
        for cve in regex:
            cve_list_repeat.append(cve)
    for item in cve_list_repeat:
        if item not in cve_list:
            cve_list.append(item)
    return cve_list


def get_links_for_bulletine():
    links = []
    for page in range(3):
        r = requests.get("https://safe-surf.ru/specialists/bulletins-nkcki/?PAGEN_1={}".format(page))
        soup = BeautifulSoup(r.text, "html.parser")
        for vuln in soup.find_all("div", "blockBase blockBulletine"):
            bulletin_pdf_url = "https://safe-surf.ru{}".format(vuln.find('h4').find('a')['href'])
            links.append(bulletin_pdf_url)
    return links


def create_pdf_file(links):
    for str in links:
        get = requests.get(str)
        name = str.replace("https://safe-surf.ru/upload/VULN/", "")
        check_file = os.path.exists(f'{PATH}/{name}')
        if check_file == 0:
            with open(f'{PATH}/{name}', 'wb') as f:
                f.write(get.content)
        else:
            print(f'file {name} already exists')


def get_name_list(path):
    name_list = os.listdir(path)
    return name_list


def remove_pdf_file(path):
    for item in path:
        os.remove(item)


# ---------------------------------------------------------------------------------------------------------------------
def get_cve_data(cve):
    template = """
### Описание

{{d.cve}}

### Дата публикации

{{d.lastModifiedDate}}

### Дата выявления

{{d.publishedDate}}

### Продукт, вендор

<details>

{% for vendor in d.product_vendor_list %}{{vendor}}
{% endfor %}

</details>

### CVSSv3 Score

{{d.score}}

### CVSSv3 Vector

{{d.vector}}

### CPE
<details>

{% if d.configurations.nodes %}
{% for conf in d.configurations.nodes %}

#### Configuration {{ loop.index }}
{% if conf.operator == 'AND'%}{% set children = conf.children %}{% else %}{% set children = [conf] %}{% endif %}{% if children|length > 1 %}
**AND:**{% endif %}{% for child in children %}{% if child.cpe_match|length > 1 %}**OR:**{% endif %}{% for cpe in child.cpe_match %}
{{ cpe.cpe23Uri | replace("*", "\*") }}{% endfor %}{% endfor %}{% endfor %}
{% endif %}
</details>

### Links
<details>

{% for link in d.links %}{{ link }}
{% endfor %}


{% if d.exploit_links %}

### Exploit

{% for exploit in d.exploit_links %}{{exploit}}
{% endfor %}
{% endif %}

</details>
    """

    pattern = ['Stack-based buffer overflow', 'Arbitrary command execution', 'Obtain sensitive information',
               'Local privilege escalation', 'Security Feature Bypass', 'Out-of-bounds read', 'Out of bounds read',
               'Denial of service', 'Denial-of-service', 'Execute arbitrary code', 'Expose the credentials',
               'Cross-site scripting (XSS)', 'Privilege escalation', 'Reflective XSS Vulnerability',
               'Execution of arbitrary programs', 'Server-side request forgery (SSRF)', 'Stack overflow',
               'Execute arbitrary commands', 'Obtain highly sensitive information', 'Bypass security',
               'Remote Code Execution', 'Memory Corruption', 'Arbitrary code execution', 'CSV Injection',
               'Heap corruption', 'Out of bounds memory access', 'Sandbox escape', 'NULL pointer dereference',
               'Remote Code Execution', 'RCE', 'Authentication Error', 'Use-After-Free', 'Use After Free',
               'Corrupt Memory', 'Execute Untrusted Code', 'Run Arbitrary Code', 'heap out-of-bounds write',
               'OS Command injection', 'Elevation of Privilege']
    try:
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
        if get_exploit_info(cve):
            exploit_links.append(get_exploit_info(cve))
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

    #parse CPE--------------------------------------------------------------------------------------------------------
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
            if (version[0] != '-' and version[0] != '*'):
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

    #check regex in cve-----------------------------------------------------------------------------------------------
        cve_name = ''
        cve_info = r.cve.description.description_data[0].value
        for item in pattern:
            if item.upper() in cve_info.upper():
                cve_name = cve + " - " + item
                break
            else:
                cve_name = cve
    #message----------------------------------------------------------------------------------------------------------
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

    #check for product_vendor-----------------------------------------------------------------------------------------
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

    # check for versions-----------------------------------------------------------------------------------------------
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

    # upload information on cve----------------------------------------------------------------------------------------
        buff_content = []
        buff_versions = []
        if re.search(r'windows', product_vendor_list[0]):
            con = {"name": "Microsoft Windows"}
            buff_content.append(con)
            buff_versions = versions
        elif re.search(r'juniper', product_vendor_list[0]):
            con = {"name": "Juniper"}
            buff_content.append(con)
            buff_versions = versions
        elif re.search(r'adaptive_security_appliance', product_vendor_list[0]):
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
                    "name": "Бюллетени НКЦКИ",
                    "id": "6-4",
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
        post = requests.post(URL, headers=headers, json=request_payload)  # Выгрузка инфы о cve в YouTrack
        return post.status_code
    except:
        pass


def email_alert(cve_list):
    recipients = []
    recipients.append(USER1)
    recipients.append(USER2)
    msg = EmailMessage()
    msg['Subject'] = 'НКЦКИ'
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


# alert on telegram bot-------------------------------------------------------------------------------------------------
def telegram_alert(message):
    sticker = random.choice(stickers)
    # Ruslan Alert
    requests.get(f"https://api.telegram.org/bot{BOT_TOKEN}/" + f"sendMessage?chat_id={CHAT_ID_R}&text={message}")
    requests.get(f"https://api.telegram.org/bot{BOT_TOKEN}/"f"sendSticker?chat_id={CHAT_ID_R}&sticker={sticker}")
    # Djenya Alert
    requests.get(f"https://api.telegram.org/bot{BOT_TOKEN}/" + f"sendMessage?chat_id={CHAT_ID_J}&text={message}")
    requests.get(f"https://api.telegram.org/bot{BOT_TOKEN}/"f"sendSticker?chat_id={CHAT_ID_J}&sticker={sticker}")


#-----------------------------------------------MAIN--------------------------------------------------------------------
headers = {
    "Accept": "application/json",
    "Authorization": "Bearer {}".format(YOU_TRACK_TOKEN),
    "Content-Type": "application/json"
}
list_summary = requests.get(MAIN_URL_PDF, headers=headers).json()  # Получение задач с YouTrack
links = get_links_for_bulletine()
create_pdf_file(links)
name_list = get_name_list(PATH)  # Получение имен скаченных файлов для парсинга
cve_line = get_cve_list(name_list)  # Получение списка cve из биллютеня НКЦКИ

broke_sum_list = []
for n in range(len(list_summary)):  # Получение описания для каждой уязвимости
    broke_sum_list.append(list_summary[n]['summary'])

sum_list = []
for item in broke_sum_list:  # Выдергивание идентификатора CVE из каждого описания уязвимости
    regex = re.search(r'CVE-\d{4}-\d{4,8}', item)
    if regex:
        sum_list.append(str(regex.group()))

vuln_list = []
for item in cve_line:  # Удаление идентификаторов CVE по которым уже заведены задачи
    if item not in sum_list:
        vuln_list.append(item)

cve_list = []
for i, item in enumerate(vuln_list):  # Заведение задач в YouTrack
    cve = vuln_list[i]
    post = get_cve_data(cve)
    if post == 200:
        cve_list.append(cve)
        print(f'{i + 1} / {len(vuln_list)} - {post}')
    else:
        print(f'{i + 1} / {len(vuln_list)} - No information for {cve}')

# email alert
'''
if cve_list:
    email_alert(cve_list)
'''
# telegram alert
if cve_list:
    if len(cve_list) == 1:
        message = f'*NKCKI*\nДобавлена информация о новой уязвимости {cve_list[0]}'
        telegram_alert(message)
    else:
        message = f'*NKCKI*\nДобавлена информация о новых уязвимостях\n {", ".join(cve_list)}'
        telegram_alert(message)


# remove pdf buffer-----------------------------------------------------------------------------------------------------
time.sleep(2)
path_to_remove_pdf = []
for item in name_list:
    path_to_remove_pdf.append(f'{PATH}/{item}')
remove_pdf_file(path_to_remove_pdf)





