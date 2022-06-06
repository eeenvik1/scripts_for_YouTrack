import requests
from bs4 import BeautifulSoup
import re
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_kb(cve):
    # print('get_kb') # DEBUG
    msrc_url = f"https://api.msrc.microsoft.com/cvrf/v2.0/Updates('{cve}')"
    get_cvrf_link = requests.get(msrc_url, verify=False)
    id_for_cvrf = re.search(r'\d{4}-\w{3}', get_cvrf_link.text)
    cvrf_url = f'https://api.msrc.microsoft.com/cvrf/v2.0/document/{id_for_cvrf[0]}'
    get_info = requests.get(cvrf_url, verify=False)
    soup = BeautifulSoup(get_info.text, "lxml")

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
            soup_get_product = BeautifulSoup(get_product.text, "lxml")
            product_buff = ''
            for item in soup_get_product.find_all('a', class_='contentTextItemSpacerNoBreakLink'):
                product_buff = item.text
            product = product_buff.strip()
            # Output: Windows 10 Version 1809 for x86-based Systems
            #link_list.append(f'[{kb}]({kb_url}) - {(product.partition("for")[2])[:-12]}')
            if product:
                # Output: 2022-01 Cumulative Update for Windows 10 Version 1809 for x86-based Systems (KB5009557)
                link_list.append(f'[{kb}]({kb_url}) - {product[:-12]}')

    return link_list

'''
cve = 'CVE-2022-26809'
link_list = get_kb(cve)
for item in link_list:
    print(item)

    format_sting_1 = item.split(']')[1].replace('(', '').replace(')', '')  # cosmetic output
    result_string = format_sting_1.split(' - ')  # cosmetic output
    print(f'{result_string[1]} - {result_string[0]}')

'''
