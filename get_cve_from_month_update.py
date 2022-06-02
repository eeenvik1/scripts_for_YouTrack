import urllib3
from bs4 import BeautifulSoup
from selenium import webdriver
import time
import re


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_get_microsoft(url):
    options = webdriver.ChromeOptions()
    path = "D:\\PycharmProjects\\scripts_for_YT\\yandexdriver.exe"  # Путь до файла с драйвером  (ЭКРАНИРОВАНИЕ!)
    driver = webdriver.Chrome(executable_path=path, options=options)
    driver.get(url)
    time.sleep(2)  # Если не успевает прогрузить страницу, то увеличить количество секунд на задержку
    page_source = driver.execute_script("return document.body.innerHTML;")
    s_response = BeautifulSoup(page_source, "html.parser")
    cve_list = []
    for item in s_response.find_all('a'):
        regex = re.search(r'CVE-\d{4}-\d{4,8}', item.text)
        if regex:
            cve_list.append(item.text)
    return cve_list


month_list = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
year_list = ['2019', '2020', '2021', '2022']  # Тут можно дополнить года
for year in year_list:
    for month in month_list:
        url_get_cve = f'https://msrc.microsoft.com/update-guide/releaseNote/{year}-{month}'
        compare_cve_list = get_get_microsoft(url_get_cve)
        print(f'{year}-{month}:')
        print(compare_cve_list)