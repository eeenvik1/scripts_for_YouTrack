import requests
import re
import urllib3
from dotenv import dotenv_values
import os


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
config = dotenv_values(dotenv_path)
YOU_TRACK_TOKEN = config.get("YOU_TRACK_TOKEN")
MAIN_URL_CHANGING = config.get("MAIN_URL_CHANGING")
YOU_TRACK_PROJECT_ID = config.get("YOU_TRACK_PROJECT_ID")
YOU_TRACK_BASE_URL = config.get("YOU_TRACK_BASE_URL")


def use_real_attack_cve():
    url_ger_real_cve = 'https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv'
    response_get_real_cve = requests.get(url_ger_real_cve, verify=False)
    real_cve_list = re.findall(r'CVE-\d{4}-\d{4,8}', response_get_real_cve.text)
    return real_cve_list


def update_custom_filed(issue_id):
    request_payload = {
        "project": {
            "id": YOU_TRACK_PROJECT_ID
        },
        "customFields": [
            {
                "name": "Использовалась в реальных атаках",
                "$type": "SingleEnumIssueCustomField",
                "value": {"name": "Да"}
            }
        ]
    }
    url_differences = f'{YOU_TRACK_BASE_URL}/issues/{issue_id}'
    diff = requests.post(url_differences, headers=headers, json=request_payload)
    return diff.status_code


# ------------------------------------------------------MAIN------------------------------------------------------------
headers = {
    "Accept": "application/json",
    "Authorization": "Bearer {}".format(YOU_TRACK_TOKEN),
    "Content-Type": "application/json"
}

list_summary = requests.get(MAIN_URL_CHANGING, headers=headers).json()  # Получение задач с YouTrack

# Получение информации по cve с YouTrack
cve_list = []  # CVE id
id_list = []  # ID Задачи
for i, item in enumerate(list_summary):
    regex = re.search(r'CVE-\d{4}-\d{4,8}', str(list_summary[i]['summary']))
    if regex is not None and list_summary[i]['customFields'][14]['value']['name'] == 'Нет':
        cve_list.append(str(regex.group()))
        id_list.append(list_summary[i]['id'])

attack_cve_list = use_real_attack_cve()
for cve in attack_cve_list:
    if cve in cve_list:
        print(update_custom_filed(id_list[cve_list.index(cve)]))