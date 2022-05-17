import requests
import re
import urllib3
from dotenv import dotenv_values
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
config = dotenv_values(dotenv_path)
YOU_TRACK_TOKEN = config.get("YOU_TRACK_TOKEN")
MAIN_URL_REMOVE = config.get("MAIN_URL_REMOVE")
URL_REMOVE = config.get("URL_REMOVE")
headers = {
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(YOU_TRACK_TOKEN),
        "Content-Type": "application/json"
    }
list_summary = requests.get(MAIN_URL_REMOVE, headers=headers).json()

buff_cve_list = []
buff_id_list = []
for i in range(len(list_summary)):
    regex = re.search(r'CVE-\d{4}-\d{4,6}', str(list_summary[i]['summary']))
    if regex is not None:
        buff_cve_list.append(str(regex.group()))
        buff_id_list.append(list_summary[i]['id'])

no_repeat_list = []
repeat_list = []
for i in range(len(buff_cve_list)):
    if buff_cve_list[i] not in no_repeat_list:
        no_repeat_list.append(buff_cve_list[i])
    else:
        repeat_list.append(buff_id_list[i])

for n, name in enumerate(repeat_list, start=1):
    URL1 = f'{URL_REMOVE}{name}'
    headers = {
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(YOU_TRACK_TOKEN),
        "Content-Type": "application/json"
    }
    delete = requests.delete(URL1, headers=headers)
    if delete.status_code == 200:
        print(f'{n} / {len(repeat_list)} - OK')
    else:
        print(f'{n} / {len(repeat_list)} - {delete.json()}')