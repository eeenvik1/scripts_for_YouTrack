#! /usr/bin/python3
import requests
import urllib3
import re
import datetime
import time
from dotenv import dotenv_values
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
config = dotenv_values(dotenv_path)

# imported variables from .env
YOU_TRACK_PROJECT_ID = config.get("YOU_TRACK_PROJECT_ID")
YOU_TRACK_BASE_URL = config.get("YOU_TRACK_BASE_URL")
MAIN_URL_CHANGING = config.get("MAIN_URL_CHANGING")
YOU_TRACK_TOKEN = config.get("YOU_TRACK_TOKEN")
MAIN_URL_FOR_RV = config.get("MAIN_URL_FOR_RV")
RV_FILTERS_LINK = config.get("RV_FILTERS_LINK")
RV_USERNAME = config.get("RV_USERNAME")
RV_PASSWORD = config.get("RV_PASSWORD")
RV_X_TOKEN = config.get("RV_X_TOKEN")
RV_NAME = config.get("RV_NAME")
RV_URL = config.get("RV_URL")

URL = str(YOU_TRACK_BASE_URL) + "/issues"

unix_time = str(time.mktime(datetime.datetime.now().timetuple()))[:-2]
session = requests.Session()


def get_csrf_token():
    global session

    url_get_token = RV_URL + f'csrfToken?{unix_time}'
    a = session.get(url_get_token, verify=False)
    return a.json()["_csrf"]


def auth(task_name, task_description, product_list):
    global session

    csrf = get_csrf_token()
    url_auth = RV_URL + 'login'
    payload_auth = {
        "username": RV_USERNAME,
        "password": RV_PASSWORD,
        "tz": "Europe/Moscow",
        "_csrf": csrf
    }

    session.post(url_auth, verify=False, data=payload_auth)  # get new csrf for POST request
    get_for_csrf_2 = session.get(RV_URL + f'csrfToken?{unix_time}', verify=False)
    csrf_2 = get_for_csrf_2.json()["_csrf"]
    headers = {
        'X-Token': RV_X_TOKEN,
        'X-Csrf-Token': csrf_2
    }

    start_date = datetime.datetime.today().strftime('%Y-%m-%d')
    date_format = datetime.datetime.strptime(start_date, '%Y-%m-%d')
    end_date = date_format + datetime.timedelta(days=10)
    duedate = str(end_date).replace(' ', 'T') + 'Z'

    # Информация по задаче
    payload_for_create_task = {
        "company_id": 4,  # ID организации
        "name": task_name,  # Example: Закрытие уязвимости CVE-2022-40444
        "type_id": 6,  # Тип задачи (6 - Работа с уязвимостями)
        "description": task_description,  # Описание задачи
        "duedate": duedate,  # Срок исполнения
        "level_id": 2,
        "assignee_ids": [151, 125]  # ID ответственных за исполнение задачи
    }
    url_for_create_task = RV_URL + 'api/v1/tm/tasks/'
    request_for_create_task = session.post(url_for_create_task, verify=False, headers=headers,
                                           data=payload_for_create_task)
    response_for_create_task = request_for_create_task.json()
    task_id = response_for_create_task['data'][0]['id']
    if request_for_create_task.status_code == 200:
        print(f'Создана задача TSK-{task_id}')
    else:
        print(request_for_create_task.text)

    # Получение информации об ID оборудования
    ids_list = []
    for product_name in product_list:
        url_get_id_active = RV_URL + f'api/v1/am/devices?_dc={unix_time}' + RV_FILTERS_LINK + f'{product_name}' + '"}]'
        request_get_id_active = session.get(url_get_id_active, verify=False, headers=headers)
        response_get_id_active = request_get_id_active.json()
        for i in range(len(response_get_id_active['data'])):
            if RV_NAME in response_get_id_active['data'][i]['assets_name']:
                ids_list.append(int(response_get_id_active['data'][i]['id']))

    # Добавление активов к задаче
    payload_add_active = {
        "ids": ids_list
    }
    # Выгрузка информации об оборудовании
    url_add_active = RV_URL + f'api/v1/tm/tasks/{task_id}/devices'
    request_add_active = session.post(url_add_active, verify=False, headers=headers, data=payload_add_active)
    if request_add_active.status_code == 200:
        print(f'Добавлено оборудование к задаче TSK-{task_id}')
    else:
        print(request_add_active.text)

    return task_id


# ----------------------------------------------MAIN--------------------------------------------------------------------
headers_main = {
    "Accept": "application/json",
    "Authorization": "Bearer {}".format(YOU_TRACK_TOKEN),
    "Content-Type": "application/json"
}
list_summary = requests.get(MAIN_URL_FOR_RV, headers=headers_main).json()  # Получение задач с YouTrack
# print(len(list_summary))  # Количество заведенных задач

# Получение задач для экспорта (наименование, ID задачи)
cve_list = []
id_list = []
for i, item in enumerate(list_summary):
    regex = re.search(r'CVE-\d{4}-\d{4,8}', str(list_summary[i]['summary']))
    # regex = re.search(r'CVE-2021-43899', str(list_summary[i]['summary']))  # DEBUG
    if regex:
        issue_state = list_summary[i]['customFields'][2]['value']['name']
        state = "Выработаны рекомендации"
        issue_status = list_summary[i]['customFields'][13]['value']['name']
        status = 'to export'
        if issue_status == status and issue_state == state:
            cve_list.append(item)
            id_list.append(list_summary[i]['id'])

# Получение продуктов
product_list = []
cve_name = ''
mitigations = ''
if cve_list:
    for i in range(len(cve_list)):
        for j in range(len(cve_list[i]['customFields'][5]['value'])):
            name_of_product = cve_list[i]['customFields'][5]['value'][j]['name'].split(' - ')[0].replace('_', ' ')
            if 'windows' in name_of_product and name_of_product.split(' ')[-1:][0].isnumeric():  # Очень хитрый костыль
                product_list.append(name_of_product)
        product_list_no_repetitions = list(set(product_list))  # Получение списка продуктов

        # Получение наименования уязвимости
        cve_name = cve_list[i]['summary']

        # Получение ID задачи в YT
        issueID = id_list[i]

        # Получение рекомендаций
        url_comments = URL + f'/{issueID}/comments?fields=text'
        comment_list = requests.get(url_comments, headers=headers_main).json()
        for item in comment_list:
            if 'Рекомендации' in item['text']:
                to_text = item['text']
                cosmetic = to_text.replace('#', '').replace('[', '').replace('](', ' -> ')
                mitigations = cosmetic.replace(')', '').replace('(', '').replace('**', '')

        # Вывод количества итераций
        print(f'{i+1} / {len(cve_list)}')
        # Создание задачи в RVision
        task_id = auth(cve_name, mitigations, product_list_no_repetitions)

        # Добавление комментария в YouTrack с номером задачи из RVision
        url_add_comment = URL + f'/{issueID}/comments'
        payload_add_comment = {
            "text": f'Решение для закрытия уязвимости доведены ответственным через RVision. TSK-{task_id}',
            "visibility": {
                "permittedGroups": [
                    {
                        "id": "1-8"
                    }
                ],
                "$type": "UnlimitedVisibility"
            }
        }
        add_comment = requests.post(url_add_comment, verify=False, headers=headers_main, json=payload_add_comment)
        if add_comment.status_code == 200:
            print(f'Добавлен комментарий к задаче {issueID}')
        else:
            print(add_comment.text)

        # Смена состояний задачи в YT
        payload_change_fields = {
            "customFields": [
                {
                    "name": "State",
                    "$type": "StateIssueCustomField",
                    "value": {"name": "Направлены рекомендации исполнителям"}
                },
                {
                    "name": "Экспорт задач",
                    "$type": "StateIssueCustomField",
                    "value": {"name": "exported"}
                }
            ]
        }
        url_change_fields = URL + f'/{issueID}'
        change_field = requests.post(url_change_fields, headers=headers_main, verify=False, json=payload_change_fields)
        if change_field.status_code == 200:
            print(f'Состояние задачи {issueID} изменилось')
        else:
            print(change_field.text)
else:
    print('Новых отресёрченных уязвимостей нет')