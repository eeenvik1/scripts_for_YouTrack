# Description
Скрипты для парсинга различных сайтов:
* Бюллетени НКЦКИ (<https://safe-surf.ru/>) - parsing_pdf.py
* Сайт <https://www.opencve.io/> - parsing_opencve.py
* Сайт <https://cvetrends.com/> - parsing_cvetrends.py
* Сайт <https://www.first.org/epss/data_stats> - add_epss.py
* [Репозиторий](https://github.com/nu11secur1ty/CVE-mitre) на гитхабе с эскполитами  - функция `get_exploit_info` в каждом из скриптов
* Сайт <https://otx/alienvault.com/> - функция `get_ttp` в скрипте `changing_all_issues.py`
* Сайт <https://attack.mitre.org/> - функция `get_mitigations` в скрипте `changing_all_issues.py`, которая получает значения из функции `get_ttp`

## Install
Для установки запустить 
```pip3 install -r requirements.txt```

## Usage
Перед началом работы необходимо создать файл `.env` и добавить в него необходимые ссылки и креды.

Создать `.env` файл

```sh
touch .env
```

Добавить креды в `.env`

```sh
# .env file
YOU_TRACK_TOKEN='<YOU_TRACK_TOKEN>'
YOU_TRACK_PROJECT_ID='<YOU_TRACK_PROJECT_ID>'
YOU_TRACK_BASE_URL='<YOU_TRACK_BASE_URL>'
MAIN_URL_ADD_EPSS='<MAIN_URL_ADD_EPSS>'
MAIN_URL_CHANGING='<MAIN_URL_CHANGING>'
MAIN_URL_CVETRENDS='<MAIN_URL_CVETRENDS>'
MAIN_URL_OPENCVE='<MAIN_URL_OPENCVE>'
MAIN_URL_PDF='<MAIN_URL_PDF>'
MAIN_URL_REMOVE='<MAIN_URL_REMOVE>'
URL_REMOVE='<URL_REMOVE>'
URL_GET_PRODUCTS='<URL_GET_PRODUCTS>'
URL_GET_VERSIONS='<URL_GET_VERSIONS>'
EMAIL_HOST='<EMAIL_HOST>'
EMAIL_PORT='<EMAIL_PORT>'
EMAIL_HOST_PASSWORD='<EMAIL_HOST_PASSWORD>'
EMAIL_HOST_USER='<EMAIL_HOST_USER>'
USER1='<USER1>' 
USER2='<USER2>'
USERNAME_OPENCVE='<USERNAME_OPENCVE>'
PASSWORD_OPENCVE='<PASSWORD_OPENCVE>'
API_KEY_ALIENVAULT='<API_KEY_ALIENVAULT>'
```

Для автоматической работы скриптов следует использовать `cron`
Рекомендуемый порядок запуска скриптов:
```
0 * * * * python3 scripts_for_YT/parsing_pdf.py # Каждую нулевую минуту
4 * * * * python3 scripts_for_YT/parsing_opencve.py # Каждую четвертую минуту
12 */3 * * * python3 scripts_for_YT/changing_all_issues.py # Каждую двенадцатую минуту, каждого третьего часа
30 * * * * python3 scripts_for_YT/add_epss.py # Каждую тридцаитую минуту
40 * * * * python3 scripts_for_YT/remove_repetitions.py # Каждую сороковую минуту
8 * * * * python3 scripts_for_YT/parsing_cvetrends.py # Каждую восьмую минуту
``` 
## Examples

### parse_alienvault.py

**Desription:**

На вход скрипт принимает список идентификаторов уязвимостей (cve). На выходе выводится список митигэйшэнов сразу в разметке Markdown.

**Input:**
```
cve_list = ['CVE-2021-27365', 'CVE-2021-28313', 'CVE-2021-28315', 'CVE-2021-32761', 'CVE-2021-40444', 'CVE-2021-44228', 'CVE-2019-17571', 'CVE-2021-43803', 'CVE-2021-43808', 'CVE-2021-41270', 'CVE-2021-34787', 'CVE-2021-40125']
```
**Usage:**
```
python3 parse_alienvault.py
```
**Output:**
```
No mitigations for CVE-2021-27365
No mitigations for CVE-2021-28313
No mitigations for CVE-2021-28315
No mitigations for CVE-2021-32761
['[M1047 - Audit ](https://attack.mitre.org/mitigations/M1047)', '[M1017 - User Training ](https://attack.mitre.org/mitigations/M1017)', '[M1028 - Operating System Configuration ](https://attack.mitre.org/mitigations/M1028)', '[M1038 - Execution Prevention ](https://attack.mitre.org/mitigations/M1038)', '[M1040 - Behavior Prevention on Endpoint ](https://attack.mitre.org/mitigations/M1040)', '[M1018 - User Account Management ](https://attack.mitre.org/mitigations/M1018)', '[M1026 - Privileged Account Management ](https://attack.mitre.org/mitigations/M1026)', '[M1042 - Disable or Remove Feature or Program ](https://attack.mitre.org/mitigations/M1042)']
['[M1017 - User Training ](https://attack.mitre.org/mitigations/M1017)', '[M1027 - Password Policies ](https://attack.mitre.org/mitigations/M1027)', '[M1032 - Multi-factor Authentication ](https://attack.mitre.org/mitigations/M1032)', '[M1018 - User Account Management ](https://attack.mitre.org/mitigations/M1018)', '[M1026 - Privileged Account Management ](https://attack.mitre.org/mitigations/M1026)']
['[M1037 - Filter Network Traffic ](https://attack.mitre.org/mitigations/M1037)', '[M1018 - User Account Management ](https://attack.mitre.org/mitigations/M1018)', '[M1040 - Behavior Prevention on Endpoint ](https://attack.mitre.org/mitigations/M1040)', '[M1026 - Privileged Account Management ](https://attack.mitre.org/mitigations/M1026)', '[M1049 - Antivirus/Antimalware ](https://attack.mitre.org/mitigations/M1049)']
No mitigations for CVE-2021-43803
No mitigations for CVE-2021-43808
No mitigations for CVE-2021-41270
No mitigations for CVE-2021-34787
No mitigations for CVE-2021-40125
```

### add_epss.py

**Desription:**

На вход скрипт принимает список идентификаторов уязвимостей (cve). На выходе выводится epss_scoring для каждой уязвимости. Что такое epss можно почитать [тут](https://www.first.org/epss/model)

### changing_all_issues.py

**Desription:**

Скрипт обновляет описание для каждой уязвимости исходя из парсинга сайтов приведенных в самом начале.

### remove repetitions.py

**Desription:**

Скрипт удаляет дублирующиеся задачи. 
