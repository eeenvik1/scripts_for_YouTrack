import requests
import urllib3
from bs4 import BeautifulSoup
from selenium import webdriver
import time
import re
from dotenv import dotenv_values
import os

dotenv_path = os.path.join(os.path.dirname(__file__), '.env')  # Путь до файла с кредами
config = dotenv_values(dotenv_path)
webdriver_path = os.path.join(os.path.dirname(__file__), 'yandexdriver.exe')  # Путь до файла с драйвером
print(webdriver_path)
# imported variables from .env
YOU_TRACK_TOKEN = 'perm:ZWVlbnZpazE=.NTItNA==.InF3oi2JMIAagbTcNgc9LrAeWbnGzz'
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
CHAT_ID_L = config.get("CHAT_ID_L")
CHAT_ID_A = config.get("CHAT_ID_A")

URL = str(YOU_TRACK_BASE_URL) + "/issues"


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_get_microsoft(url):
    options = webdriver.ChromeOptions()
    path = webdriver_path
    driver = webdriver.Chrome(executable_path=webdriver_path, options=options)
    driver.get(url)
    time.sleep(2)
    page_source = driver.execute_script("return document.body.innerHTML;")
    s_response = BeautifulSoup(page_source, "html.parser")
    cve_list = []
    for item in s_response.find_all('a'):
        regex = re.search(r'CVE-\d{4}-\d{4,8}', item.text)
        if regex:
            cve_list.append(item.text)
    return cve_list


month_list = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
year_list = ['2019', '2020', '2021', '2022']
for year in year_list:
    for month in month_list:
        url_get_cve = f'https://msrc.microsoft.com/update-guide/releaseNote/{year}-{month}'
        compare_cve_list = get_get_microsoft(url_get_cve)
        headers_main = {
            "Accept": "application/json",
            "Authorization": "Bearer {}".format(YOU_TRACK_TOKEN),
            "Content-Type": "application/json"
        }
        list_summary = requests.get(MAIN_URL_CHANGING, headers=headers_main).json()  # Получение задач с YouTrack

        cve_list = []
        id_list = []
        for i, item in enumerate(list_summary):
            regex = re.search(r'CVE-\d{4}-\d{4,8}', str(list_summary[i]['summary']))
            if regex:
                issue_state = list_summary[i]['customFields'][2]['value']['name']
                state_1 = "Won't fix"
                state_2 = "Выработаны рекомендации"
                state_3 = "Направлены рекомендации исполнителям"
                # if issue_state == 'Open' or issue_state == 'In Progress':
                # Обновляется информация только для актуальных задач:
                if issue_state != state_1 and issue_state != state_2 and issue_state != state_3:
                #if regex.group() == 'CVE-2022-26808':  #DEBUG
                    cve_list.append(str(regex.group()))
                    id_list.append(list_summary[i]['id'])

        cve_name = []
        cve_id = []
        for cve in compare_cve_list:
            if cve in cve_list:
                cve_name.append(cve)
                cve_id.append(id_list[cve_list.index(cve)])

        VM_list = []
        for IssueID in cve_id:
            url_get_VM = f'https://vm-proval.myjetbrains.com/youtrack/api/issues/{IssueID}?fields=idReadable'
            response_get_VM = requests.get(url_get_VM, headers=headers_main, verify=False)
            buff = response_get_VM.json()
            VM_list.append(buff['idReadable'])
        print(cve_name)

        for i in range(1, len(VM_list)):
            payload = {
                "query": f"relates to {VM_list[0]}",
                "issues": [
                    {
                        'idReadable': f'{VM_list[i]}'
                    }
                ]
            }
            url_add_relations = f'https://vm-proval.myjetbrains.com/youtrack/api/commands'
            response_add_relations = requests.post(url_add_relations, json=payload, headers=headers_main, verify=False)
            print(response_add_relations.json())

            ############################################################
            text = f'''Уязвимость закрывается обновлением в рамках
                [{year}-{month} обновлений Windows](https://msrc.microsoft.com/update-guide/releaseNote/2021-May).
            Список обновлений приведен в [связанной задаче](https://vm-proval.myjetbrains.com/youtrack/issue/{VM_list[0]}).'''

            payload_add_comment = {
                "text": text,
                "visibility": {
                    "permittedGroups": [
                        {
                            "id": "1-8"
                        }
                    ],
                    "$type": "UnlimitedVisibility"
                }
            }
            url_add_comment = URL + f'/{cve_id[i]}/comments'
            add_comment = requests.post(url_add_comment, verify=False, headers=headers_main, json=payload_add_comment)
            print(add_comment.json())

            payload_change_fields = {
                "customFields": [
                    {
                        "name": "State",
                        "$type": "StateIssueCustomField",
                        "value": {"name": "Выработаны рекомендации"}
                    },
                    {
                        "name": "Контур",
                        "$type": "MultiUserIssueCustomField",
                        "value": [{"name": "Платформа"}]
                    },
                ]
            }
            url_change_fields_1 = URL + f'/{cve_id[0]}'
            change_field_1 = requests.post(url_change_fields_1, headers=headers_main, verify=False, json=payload_change_fields)
            print(change_field_1.json())
            url_change_fields = URL + f'/{cve_id[i]}'
            change_field = requests.post(url_change_fields, headers=headers_main, verify=False, json=payload_change_fields)
            print(change_field.json())




'''
url_get_cve = 'https://msrc.microsoft.com/update-guide/releaseNote/2021-May'
IssueID_1 = '2-26260'  # CVE-2019-1358
IssueID_2 = '2-25931'  # CVE-2019-1359

payload = {
  "query": "relates to VM-5087",
  "issues": [
    {
      'idReadable': 'VM-4758'
    }
  ]
}
url_2 = f'https://vm-proval.myjetbrains.com/youtrack/api/commands'
#response_get = requests.get(url, headers=headers_main)
#print(response_get.json())
#response_post = requests.post(url_2, json=payload, headers=headers_main, verify=False)
#print(response_post.json())
'''



