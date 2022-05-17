#! /usr/bin/python3
import csv
import os
import urllib3
import requests
import re
import gzip
import shutil
from dotenv import dotenv_values


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
config = dotenv_values(dotenv_path)
YOU_TRACK_TOKEN = config.get("YOU_TRACK_TOKEN")
YOU_TRACK_PROJECT_ID = config.get("YOU_TRACK_PROJECT_ID")
YOU_TRACK_BASE_URL = config.get("YOU_TRACK_BASE_URL")
MAIN_URL_ADD_EPSS = config.get("MAIN_URL_ADD_EPSS")

PATH = os.path.join(os.path.dirname(__file__), 'for_add_epss')
filename = f'{PATH}/DATA.csv'
fileout = f'{PATH}/DATA1.csv'
buffer = f'{PATH}/tar.csv.gz'

def get_data_file():
    data_link = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    response = requests.get(data_link)
    with open(buffer, 'wb') as f:
        f.write(response.content)
    with gzip.open(buffer, 'rb') as f_in:
        with open(filename, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)


def info_data(filename):
    with open(filename) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        my_file = open(fileout, "w")
        for row in csv_reader:
            try:
                epss = str(round(float(str(100 / (1 / float(row[1])))[0:5]), 2))
                data = str(row[0] + ',' + epss + '\n')
                my_file.write(data)
            except:
                pass
        my_file.close()


def payload(procent, id):
    headers = {
        "Accept": "application/json",
        "Authorization": "Bearer {}".format(YOU_TRACK_TOKEN),
        "Content-Type": "application/json"
    }
    request_payload = {
        "project": {
            "id": YOU_TRACK_PROJECT_ID
        },
        "customFields": [
            {
                "name": "EPSS",
                "$type": "SimpleIssueCustomField",
                "value": float(procent)
            }
        ]
    }
    url_differences = f'{YOU_TRACK_BASE_URL}/issues/{id}'
    diff = requests.post(url_differences, headers=headers, json=request_payload)
    return diff.status_code  # DEBUG


# --------------------------------------------MAIN-----------------------------------------------------------------------
get_data_file()
info_data(filename)
cve_line = []
procent_line = []
with open(fileout) as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    for row in csv_reader:
        cve_line.append(row[0])
        procent_line.append(row[1])


headers = {
    "Accept": "application/json",
    "Authorization": "Bearer {}".format(YOU_TRACK_TOKEN),
    "Content-Type": "application/json"
}
list_summary = requests.get(MAIN_URL_ADD_EPSS, headers=headers).json()  # Получение задач с YouTrack

buff_cve_list = []
buff_id_list = []
for i, item in enumerate(list_summary):
    regex = re.search(r'CVE-\d{4}-\d{4,8}', str(list_summary[i]['summary']))
    if regex is not None:
        buff_cve_list.append(str(regex.group()))
        buff_id_list.append(list_summary[i]['id'])

cve_list = []
procent_list = []
id_list = []
for i, item in enumerate(cve_line):
    for j, jtem in enumerate(buff_cve_list):
        if cve_line[i] == buff_cve_list[j]:
            cve_list.append(cve_line[i])
            procent_list.append(procent_line[i])
            id_list.append(buff_id_list[j])

for i, item in enumerate(cve_list):
    print(f'{i + 1} / {len(cve_list)} - {payload(procent_list[i], id_list[i])}')

# ----------------------------------REMOVE_BUFFER_FILES------------------------------------------------------------------
os.remove(filename)
os.remove(fileout)
os.remove(buffer)



