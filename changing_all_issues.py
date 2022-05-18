#! /usr/bin/python3
import jinja2
import requests
from bs4 import BeautifulSoup
import urllib3
from cpe import CPE
import nvdlib
import ast
import re
import json
import datetime
import time
import smtplib
from email.message import EmailMessage
from dotenv import dotenv_values
import os
import random
from stickers import stickers

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
config = dotenv_values(dotenv_path)
YOU_TRACK_TOKEN = config.get("YOU_TRACK_TOKEN")
MAIN_URL_CHANGING = config.get("MAIN_URL_CHANGING")
YOU_TRACK_PROJECT_ID = config.get("YOU_TRACK_PROJECT_ID")
YOU_TRACK_BASE_URL = config.get("YOU_TRACK_BASE_URL")
URL_GET_PRODUCTS = config.get("URL_GET_PRODUCTS")
URL_GET_VERSIONS = config.get("URL_GET_VERSIONS")
API_KEY_ALIENVAULT = config.get("API_KEY_ALIENVAULT")
EMAIL_HOST = config.get("EMAIL_HOST")
EMAIL_PORT = config.get("EMAIL_PORT")
EMAIL_HOST_PASSWORD = config.get("EMAIL_HOST_PASSWORD")
EMAIL_HOST_USER = config.get("EMAIL_HOST_USER")
USER1 = config.get("USER1")
BOT_TOKEN = config.get("BOT_TOKEN")
CHAT_ID_J = config.get("CHAT_ID_J")
CHAT_ID_R = config.get("CHAT_ID_R")

URL = str(YOU_TRACK_BASE_URL) + "/issues"


# parse mitre.org
def get_mitigations(tactic_id):
    # print("get_mitigations") # DEBUG
    tactic_url = f'https://attack.mitre.org/techniques/{tactic_id}'
    r_get_tactic_info = requests.get(tactic_url)
    s_get_tactic_info = BeautifulSoup(r_get_tactic_info.text, 'html.parser')

    #  0 - Procedure Examples
    #  1 - Mitigations
    #  2 - Detection
    try:
        mitigations = s_get_tactic_info.find_all("table", class_="table table-bordered table-alternate mt-2")[1].text
        buff_string_1 = str(mitigations).replace("ID", "").replace("Mitigation", "").replace("Description", "").replace(
            "\n\n", "")
        buff_list = buff_string_1.split('\n')
        buff_list.pop(0)  # Remove empty element, index - 0
        return_list = []
        for count in range(int(len(buff_list) / 3)):
            id_mit = buff_list[count * 3].rstrip().lstrip()
            name_mit = buff_list[count * 3 + 1].rstrip().lstrip()
            desc_mit = buff_list[count * 3 + 2].rstrip().lstrip()
            return_list.append(f'[{id_mit} - {name_mit}](https://attack.mitre.org/mitigations/{id_mit}) - {desc_mit}')
        return return_list
    except:
        pass


# parse alienvault.com-------------------------------------------------------------------------------------------------
def get_ttp(cve):
    # print('get_ttp') # DEBUG
    headers_alienvault = {'X-OTX-API-KEY': API_KEY_ALIENVAULT}
    url = f'https://otx.alienvault.com/api/v1/indicators/cve/{cve}'
    pattern = '{"detail": "endpoint not found"}'
    r_get_cve_info = requests.get(url, headers=headers_alienvault)
    s_get_cve_info = BeautifulSoup(r_get_cve_info.text, 'lxml')
    tactic_list = []
    if str(s_get_cve_info.p.contents).replace("['", "").replace("']", "") == pattern:
        print(f'no information for {cve}')  # DEBUG
    else:
        content = json.loads(str(s_get_cve_info.p).replace("<p>", "").replace("</p>", ""))
        count = int(content['pulse_info']['count'])
        subs_list = []
        for i in range(count):
            subs_list.append(content['pulse_info']['pulses'][i]['subscriber_count'])
        tactic_list = []
        for i, item in enumerate(subs_list):
            max_test = max(subs_list)
            if content['pulse_info']['pulses'][i]['attack_ids']:
                for j in range(len(content['pulse_info']['pulses'][i]['attack_ids'])):
                    tactic_list.append(content['pulse_info']['pulses'][i]['attack_ids'][j]['id'])
                break
            else:
                subs_list.remove(max_test)
        else:
            return f'NO TTP'
    tactic_list = list(set(tactic_list))  # replace replications
    technique_list = []
    for i, item in enumerate(tactic_list):
        if len(str(item)) > 6:
            technique_list.append(str(item).replace(".", "/"))

    result_list = []
    if technique_list:
        for tactic_id in technique_list:
            if get_mitigations(tactic_id):
                for item in get_mitigations(tactic_id):
                    result_list.append(item)
        return list(set(result_list))
    else:
        for tactic_id in tactic_list:
            if get_mitigations(tactic_id):
                for item in get_mitigations(tactic_id):
                    result_list.append(item)
        return list(set(result_list))


# check info for cve on microsoft--------------------------------------------------------------------------------------
def check_microsoft(cve):
    # print('check_microsoft') # DEBUG
    msrc_url = f"https://api.msrc.microsoft.com/cvrf/v2.0/Updates('{cve}')"
    get_cvrf_link = requests.get(msrc_url, verify=False)
    return get_cvrf_link.status_code


# get KB links for cve--------------------------------------------------------------------------------------------------
def get_kb(cve):
    # print('get_kb') # DEBUG
    msrc_url = f"https://api.msrc.microsoft.com/cvrf/v2.0/Updates('{cve}')"
    get_cvrf_link = requests.get(msrc_url, verify=False)
    id_for_cvrf = re.search(r'\d{4}-\w{3}', get_cvrf_link.text)
    cvrf_url = f'https://api.msrc.microsoft.com/cvrf/v2.0/document/{id_for_cvrf[0]}'
    get_info = requests.get(cvrf_url, verify=False)
    soup = BeautifulSoup(get_info.text, "html.parser")
    parse_list = []
    buff = ''
    for item in soup.text:
        if item == '\n':
            parse_list.append(buff)
            buff = ''
        else:
            buff += item
    parse_string = ''
    for j, item in enumerate(parse_list):
        regex = re.findall(cve, parse_list[j])
        if regex:
            parse_string = parse_list[j]
    kb_list = re.findall(r'KB\d{7}', parse_string)
    not_remove_list_of_kb = []
    for kb in kb_list:
        if kb not in not_remove_list_of_kb:
            not_remove_list_of_kb.append(kb)
    link_list = []
    for kb in not_remove_list_of_kb:
        kb_url = f'https://catalog.update.microsoft.com/v7/site/Search.aspx?q={kb}'
        test = requests.get(kb_url, verify=False)
        if test.status_code == 200:
            url_get_product = f'https://www.catalog.update.microsoft.com/Search.aspx?q={kb}'
            get_product = requests.get(url_get_product, verify=False)
            soup_get_product = BeautifulSoup(get_product.text, "html.parser")
            product_buff = ''
            for item in soup_get_product.find_all('a', class_='contentTextItemSpacerNoBreakLink'):
                product_buff = item.text
            product = product_buff.strip()
            # Output: Windows 10 Version 1809 for x86-based Systems
            # link_list.append(f'[{kb}]({kb_url}) - {(product.partition("for")[2])[:-12]}')
            if product:
                # Output: 2022-01 Cumulative Update for Windows 10 Version 1809 for x86-based Systems (KB5009557)
                link_list.append(f'[{kb}]({kb_url}) - {product}')
    return link_list


# check nu11secur1ty----------------------------------------------------------------------------------------------------
def get_exploit_info(cve):
    # print('get_exploit_info') # DEBUG
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
            default_link = f'**nu11secur1ty** - https://github.com/nu11secur1ty/CVE-mitre/tree/main/{cve}'
    return default_link


# main function for upload information on YT----------------------------------------------------------------------------
def get_cve_data(cve, id):
    # print('get_cve_data') # DEBUG
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


{%if d.kb_links %}

### Решение от майкрософт
<details>
<summary>Установить следующие обновления безопасности</summary>

{% for link in d.kb_links %}{{link}}
{% endfor %}
{% endif %}

</details>


{%if d.mitigations_links %}

### Mitigations от MITRE
<details>
<summary>Mitigation_ID and link</summary>

{% for link in d.mitigations_links %}{{link}}
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

        # parse CPE--------------------------------------------------------------------------------------------------
        product_vendor_list = []
        product_image_list = []
        version_list = []
        update_list = []
        for cpe in cpe_for_product_vendors:
            cpe_parsed = CPE(cpe)
            product = cpe_parsed.get_product()
            vendor = cpe_parsed.get_vendor()
            product_vendor = vendor[0] + " " + product[0] if product != vendor else product[0]
            product_vendor_list.append(product_vendor)
            product_image_list.append(product[0])
            version = cpe_parsed.get_version()
            update = cpe_parsed.get_update()
            update_list.append(update)
            if version[0] != '-' and version[0] != '*':
                version_list.append(f'{product[0]} - {version[0]}')

        temp1 = []
        for item_1 in version_list:
            if item_1 not in temp1:
                temp1.append(item_1)
        versions = []
        for item_2 in temp1:
            ver = {"name": item_2}
            versions.append(ver)

        prod = []
        for item_3 in product_image_list:
            if item_3 not in prod:
                prod.append(item_3)

        content = []
        for item_4 in product_vendor_list:
            con = {"name": item_4}
            content.append(con)

        value = "Да"
        if not exploit_links:
            value = "Нет"

        # check regex in cve------------------------------------------------------------------------------------------
        cve_name = ''
        cve_info = r.cve.description.description_data[0].value
        for item_5 in pattern:
            if item_5.upper() in cve_info.upper():
                cve_name = cve + " - " + item_5
                break
            else:
                cve_name = cve

        # check kb in cve----------------------------------------------------------------------------------------------
        kb_links = ''
        try:
            if check_microsoft(cve) == 200:
                kb_links = get_kb(cve)
        except:
            pass

        # check mitigations for cve-------------------------------------------------------------------------------------
        mitigations_links = ''
        try:
            links_mitigations_mitre = get_ttp(cve)
            value_mitigations = 'Нет'
            if links_mitigations_mitre != 'NO TTP' and links_mitigations_mitre:
                mitigations_links = links_mitigations_mitre
                value_mitigations = 'Да'
        except:
            value_mitigations = 'Нет'

        # message-------------------------------------------------------------------------------------------------------
        data = {
            'cve': cve_info,
            'lastModifiedDate': r.lastModifiedDate[:-7],
            'publishedDate': r.publishedDate[:-7],
            'configurations': cpe_nodes,
            'score': score,
            'vector': vector,
            'links': links,
            'product_vendor_list': prod,
            'exploit_links': exploit_links,
            'kb_links': kb_links,
            'mitigations_links': mitigations_links
        }
        message = jinja2.Template(template).render(d=data)

        # check for product_vendor-------------------------------------------------------------------------------------
        headers_for_data_prod = {
            "Accept": "application/json",
            "Authorization": "Bearer {}".format(YOU_TRACK_TOKEN),
            "Content-Type": "application/json"
        }
        data_prod = requests.get(URL_GET_PRODUCTS, headers=headers_for_data_prod).json()

        upload_prod = []
        for buff in product_vendor_list:
            upload_prod.append(buff)

        prod_vend = []
        for i in data_prod:
            prod_vend.append(i['name'])

        temp = []
        for upload_1 in upload_prod:
            if upload_1 not in prod_vend:
                temp.append(upload_1)

        for upload in temp:
            payload = {
                "id": "0",
                "&type": "FieldStyle",
                "name": upload
            }
            requests.post(URL_GET_PRODUCTS, headers=headers_for_data_prod, json=payload)

        # check for versions--------------------------------------------------------------------------------------------
        data_ver = requests.get(URL_GET_VERSIONS, headers=headers_for_data_prod).json()
        ver_list = []
        for item_6 in data_ver:
            ver_list.append(item_6['name'])

        temp2 = []
        for item_7 in temp1:
            if item_7 not in ver_list:
                temp2.append(item_7)

        for upload in temp2:
            payload = {
                "id": "0",
                "&type": "FieldStyle",
                "name": upload
            }
            requests.post(URL_GET_VERSIONS, headers=headers_for_data_prod, json=payload)

        # upload information on cve-------------------------------------------------------------------------------------
        buff_content = []
        buff_versions = []
        if product_vendor_list:
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
                {
                    "name": "Есть mitigation",
                    "$type": "SingleEnumIssueCustomField",
                    "value": {"name": value_mitigations}
                },
            ]
        }

        url_differences = f'{YOU_TRACK_BASE_URL}/issues/{id}'
        diff = requests.post(url_differences, headers=headers_for_data_prod, json=request_payload)
        return diff.status_code
        # return request_payload  # DEBUG

    except:
        now_time = datetime.datetime.now()
        message = f'По состоянию на {now_time.strftime("%d-%m-%Y %H:%M")} информация об уязвимости отсутствует'
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer {}".format(YOU_TRACK_TOKEN),
            "Content-Type": "application/json"
        }
        request_payload = {
            "project": {
                "id": YOU_TRACK_PROJECT_ID
            },
            "summary": cve,
            "description": message,
        }
        url_differences = f'{YOU_TRACK_BASE_URL}/issues/{id}'
        diff = requests.post(url_differences, headers=headers, json=request_payload)
        return diff.status_code


# alert on mail---------------------------------------------------------------------------------------------------------
def email_alert(time_start, time_stop):
    recipients = []
    recipients.append(USER1)
    msg = EmailMessage()
    msg['Subject'] = 'сhanging_issues'
    msg['From'] = EMAIL_HOST_USER
    msg['To'] = ", ".join(recipients)
    body = f'Программа начала работу {time_start}, отработала - {time_stop}'
    msg.set_content(body)
    msg.set_content(body)
    smtp_server = smtplib.SMTP_SSL(host=EMAIL_HOST, port=EMAIL_PORT)
    smtp_server.login(user=EMAIL_HOST_USER, password=EMAIL_HOST_PASSWORD)
    smtp_server.send_message(msg)
    print('Email sent {}'.format(msg['Subject']))


#alert on telegram bot--------------------------------------------------------------------------------------------------
def telegram_alert(message):
    sticker = random.choice(stickers)
    # Ruslan Alert
    requests.get(f"https://api.telegram.org/bot{BOT_TOKEN}/" + f"sendMessage?chat_id={CHAT_ID_R}&text={message}&parse_mode=markdown")
    requests.get(f"https://api.telegram.org/bot{BOT_TOKEN}/"f"sendSticker?chat_id={CHAT_ID_R}&sticker={sticker}")
    # Djenya Alert
    requests.get(f"https://api.telegram.org/bot{BOT_TOKEN}/" + f"sendMessage?chat_id={CHAT_ID_J}&text={message}&parse_mode=markdown")
    requests.get(f"https://api.telegram.org/bot{BOT_TOKEN}/"f"sendSticker?chat_id={CHAT_ID_J}&sticker={sticker}")


# convert sec to normak time like 01:35:52------------------------------------------------------------------------------
def convert_to_preferred_format(sec):
    sec = sec % (24 * 3600)
    hour = sec // 3600
    sec %= 3600
    min = sec // 60
    sec %= 60
    return "%02d:%02d:%02d" % (hour, min, sec)

# ----------------------------------------------MAIN--------------------------------------------------------------------
now = datetime.datetime.now()
time_start = now.strftime("%d-%m-%Y %H:%M")
start_time = time.time()
headers_main = {
    "Accept": "application/json",
    "Authorization": "Bearer {}".format(YOU_TRACK_TOKEN),
    "Content-Type": "application/json"
}
list_summary = requests.get(MAIN_URL_CHANGING, headers=headers_main).json()  # Получение задач с YouTrack
print(len(list_summary))  # Количество заведенных задач

cve_list = []
id_list = []

for i, item in enumerate(list_summary):
    regex = re.search(r'CVE-\d{4}-\d{4,8}', str(list_summary[i]['summary']))
    # regex = re.search(r'CVE-2021-43899', str(list_summary[i]['summary']))  # DEBUG
    if regex:
        issue_state = list_summary[i]['customFields'][2]['value']['name']
        state_1 = "Won't fix"
        state_2 = "Выработаны рекомендации"
        state_3 = "Направлены рекомендации исполнителям"
        # if issue_state == 'Open' or issue_state == 'In Progress':
        # Обновляется информация только для актуальных задач:
        if issue_state != state_1 and issue_state != state_2 and issue_state != state_3:
            cve_list.append(str(regex.group()))
            id_list.append(list_summary[i]['id'])

for i, item in enumerate(cve_list):
    # Перебор с конца списка
    # print(f'{i + 1} / {len(cve_list)} - {get_cve_data(cve_list[len(cve_list) - i - 1], id_list[len(cve_list) -
    # i - 1])} - {cve_list[len(cve_list) - i - 1]}')
    # Прямой перебор по списку
    result_status_code = get_cve_data(cve_list[i], id_list[i])
    result_string = f'{i + 1} / {len(cve_list)} ({cve_list[i]})'
    subtraction = len(result_string) - 26
    escape = ' '
    print(f'{result_string}{escape*abs(subtraction)} - {result_status_code}')  # Красивый вывод информации
    # print(f'{i + 1} / {len(cve_list)} ({cve_list[i]}) - {result_status_code}')

time_stop = "за %s секунд" % (time.time() - start_time)
current_time = str(time.time() - start_time)
super_time = convert_to_preferred_format(int(current_time.split(".")[0]))
start_date = time_start.split(" ")[0]
start_time = time_start.split(" ")[1]
message = f'*CHANGING*\nПрограмма начала работу {start_date} в {start_time} и отработала за {super_time}'
# telegram alert
telegram_alert(message)
# email_alert(time_start, time_stop)


# DEBUG ONLY
'''
for i in range(len(cve_list)):
    if cve_list[i] == 'CVE-2017-0213':
        print(cve_list[i])
        print(id_list[i])

print(get_cve_data('CVE-2021-43256', '2-20142'))
# print(get_kb('CVE-2017-0213'))
'''