import urllib3
from bs4 import BeautifulSoup
from selenium import webdriver
import time
import re
import datetime
import os
from get_kb import get_kb


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
webdriver_path = os.path.join(os.path.dirname(__file__), 'yandexdriver.exe')


def get_cve_from_microsoft(url):
    options = webdriver.ChromeOptions()
    driver = webdriver.Chrome(executable_path=webdriver_path, options=options)
    driver.get(url)
    time.sleep(3)  # Если не успевает прогрузить страницу, то увеличить количество секунд на задержку
    page_source = driver.execute_script("return document.body.innerHTML;")
    s_response = BeautifulSoup(page_source, "html.parser")
    cve_list = []
    for item in s_response.find_all('a'):
        regex = re.search(r'CVE-\d{4}-\d{4,8}', item.text)
        if regex:
            cve_list.append(item.text)
    return cve_list

# Вывод списков cve по месяцам и годам
'''
month_list = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
year_list = ['2018', '2019', '2020', '2021', '2022']  # Тут можно дополнить года
for year in year_list:
    for month in month_list:
        url_get_cve = f'https://msrc.microsoft.com/update-guide/releaseNote/{year}-{month}'
        compare_cve_list = get_get_microsoft(url_get_cve)
        print(f'{year}-{month}:')
        print(compare_cve_list)
'''

'''Список CVE на текущий месяц
Обновления выходят каждый второй вторник каждого месяца, поэтому рекомендуемый порядок запуска в кроне:
0 0 15 * * python3 get_cve_from_month_update.py'''
year = datetime.datetime.today().strftime('%Y')
month = datetime.datetime.today().strftime('%B')[0:3]
url_get_cve = f'https://msrc.microsoft.com/update-guide/releaseNote/{year}-{month}'
compare_cve_list = get_cve_from_microsoft(url_get_cve)
print(f'{year}-{month}:')

'''Можно подтянуть функцию из скрипта get_kb.py, чтобы "на лету" получать список необходимых
для закрытия уязвимостей обновлений безопасности (KB)'''

for cve in compare_cve_list:
    update_list = get_kb(cve)
    print(cve)
    for item in update_list:
        print(item)
