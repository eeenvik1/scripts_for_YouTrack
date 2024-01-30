import requests
import urllib3
from bs4 import BeautifulSoup
import os
import zipfile
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
PATH = os.path.join(os.path.dirname(__file__), 'bulletins')

def get_links_for_bulletine():
    links = []
    for page_number in range(1):
        r = requests.get(f"https://safe-surf.ru/specialists/bulletins-nkcki/?PAGEN_1={page_number+1}")
        soup = BeautifulSoup(r.text, "html.parser")
        for vuln in soup.find_all('div', class_='cell-value'):
            a_tags = vuln.find_all('a')
            for tag in a_tags:
                href = tag.get('href')
                if href and "json.zip" in href and f"https://safe-surf.ru{href}" not in links:
                    links.append(f"https://safe-surf.ru{href}")
    return links

def download_json(url, directory="bulletins"):
    response = requests.get(url)
    response.raise_for_status()

    filename = os.path.basename(url.split("/")[-1])
    file_path = os.path.join(directory, filename)
    with open(file_path, "wb") as file:
        file.write(response.content)

    with zipfile.ZipFile(file_path, "r") as zip_ref:
        zip_ref.extractall(directory)


def get_info_json():
    files = []
    for i in os.listdir(PATH):
        if "zip" not in i:
            files.append(i)
    for file in files:
        with open(f"bulletins\\{file}", encoding='utf-8') as f:
            json_data = f.read()

        data = json.loads(json_data)
        total = data['total']
        for j in range(total):
            mitre = data["data"][j]["vuln_id"]["MITRE"]
            date_published = data["data"][j]["date_published"]
            date_updated = data["data"][j]["date_updated"]
            print("-------------------------------------------------------------------")
            print("MITRE:", mitre)
            print("date_published:", date_published)
            print("date_updated:", date_updated)


def remove_data():
    for file in os.listdir(PATH):
        os.remove(f"bulletins\\{file}")


links = get_links_for_bulletine()
for link in links:
    download_json(link)
    get_info_json()
remove_data()


