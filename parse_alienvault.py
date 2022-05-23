import requests
from bs4 import BeautifulSoup
import json
import time

API_KEY_ALIENVAULT = 'c63733bf4b4e763170cdda3b9b451c95dd2994aa07e5d4d4a4b216fd47275aed' # old api key

def get_mitigations(tactic_id):
    tactic_url = f'https://attack.mitre.org/techniques/{tactic_id}'
    r_get_tactic_info = requests.get(tactic_url)
    s_get_tactic_info = BeautifulSoup(r_get_tactic_info.text, 'html.parser')

    #  0 - Procedure Examples
    #  1 - Mitigations
    #  2 - Detection
    try:
        mitigations = s_get_tactic_info.find_all("table", class_="table table-bordered table-alternate mt-2")[1].text
        buff_string_1 = str(mitigations).replace("ID", "").replace("Mitigation", "").replace("Description", "").replace("\n\n", "")
        buff_list = buff_string_1.split('\n')
        buff_list.pop(0)  # Remove empty element, index - 0
        return_list = []
        for i in range(int(len(buff_list) / 3)):
            id_mit = buff_list[i*3].rstrip().lstrip()
            name_mit = buff_list[i*3+1].rstrip().lstrip()
            desc_mit = buff_list[i*3+2].rstrip().lstrip()
            return_list.append(f'[{id_mit} - {name_mit}](https://attack.mitre.org/mitigations/{id_mit}) - {desc_mit}')
        return return_list
    except:
        pass

def get_ttp(cve):
    headers = {'X-OTX-API-KEY': API_KEY_ALIENVAULT}
    url = f'https://otx.alienvault.com/api/v1/indicators/cve/{cve}'
    pattern = '{"detail": "endpoint not found"}'
    r_get_cve_info = requests.get(url, headers=headers)
    s_get_cve_info = BeautifulSoup(r_get_cve_info.text, 'lxml')
    tactic_list = []
    if str(s_get_cve_info.p.contents).replace("['", "").replace("']", "") == pattern:
        print(f'no information for {cve}')  # DEBUG
    else:
        content = json.loads(str(s_get_cve_info.p).replace("<p>", "").replace("</p>",""))
        count = int(content['pulse_info']['count'])
        if count != 0:
            for i in range(count):
                for j in range(len(content['pulse_info']['pulses'][i]['attack_ids'])):
                    tactic_list.append(content['pulse_info']['pulses'][i]['attack_ids'][j]['id'])
        else:
            return f'NO TTP'
    tactic_list = list(set(tactic_list))  # replace replications
    technique_list = []
    for i, item in enumerate(tactic_list):
        if len(str(item)) > 6:
            technique_list.append(str(item).replace(".", "/"))

    result_list = []
    if technique_list:
        for tactic_id in technique_list:
            if get_mitigations(tactic_id):
                for item in get_mitigations(tactic_id):
                    result_list.append(item)
        return list(set(result_list))
    else:
        for tactic_id in tactic_list:
            if get_mitigations(tactic_id):
                for item in get_mitigations(tactic_id):
                    result_list.append(item)
        return list(set(result_list))

def get_ttp_1(cve):
    headers = {'X-OTX-API-KEY': API_KEY_ALIENVAULT}
    url = f'https://otx.alienvault.com/api/v1/indicators/cve/{cve}'
    pattern = '{"detail": "endpoint not found"}'
    r_get_cve_info = requests.get(url, headers=headers)
    s_get_cve_info = BeautifulSoup(r_get_cve_info.text, 'lxml')
    tactic_list = []
    if str(s_get_cve_info.p.contents).replace("['", "").replace("']", "") == pattern:
        print(f'no information for {cve}')  # DEBUG
    else:
        content = json.loads(str(s_get_cve_info.p).replace("<p>", "").replace("</p>", ""))
        count = int(content['pulse_info']['count'])
        subs_list = []
        for i in range(count):
            subs_list.append(content['pulse_info']['pulses'][i]['subscriber_count'])
        print(subs_list)
        tactic_list = []
        for i, item in enumerate(subs_list):
            max_test = max(subs_list)
            if content['pulse_info']['pulses'][i]['attack_ids']:
                for j in range(len(content['pulse_info']['pulses'][i]['attack_ids'])):
                    tactic_list.append(content['pulse_info']['pulses'][i]['attack_ids'][j]['id'])
                break
            else:
                subs_list.remove(max_test)
        else:
            return f'NO TTP'
    tactic_list = list(set(tactic_list))  # replace replications
    technique_list = []
    for i, item in enumerate(tactic_list):
        if len(str(item)) > 6:
            technique_list.append(str(item).replace(".", "/"))

    result_list = []
    if technique_list:
        for tactic_id in technique_list:
            if get_mitigations(tactic_id):
                for item in get_mitigations(tactic_id):
                    result_list.append(item)
        return list(set(result_list))
    else:
        for tactic_id in tactic_list:
            if get_mitigations(tactic_id):
                for item in get_mitigations(tactic_id):
                    result_list.append(item)
        return list(set(result_list))


# DEBUG ONLY
#cve = 'CVE-2021-4034'
cve = 'CVE-2021-42001'
mit = 'T1059/001'   
# print(get_ttp(cve))
a = get_ttp_1(cve)
b = get_ttp(cve)
print(len(a))
print(len(b))


'''
start_time = time.time()
print(start_time)
cve_list = ['CVE-2021-27365', 'CVE-2021-28313', 'CVE-2021-28315', 'CVE-2021-32761', 'CVE-2021-40444', 'CVE-2021-44228', 'CVE-2019-17571', 'CVE-2021-43803', 'CVE-2021-43808', 'CVE-2021-41270', 'CVE-2021-34787', 'CVE-2021-40125']
for cve in cve_list:
    links_mitigations_mitre = get_ttp(cve)
    if links_mitigations_mitre != 'NO TTP' and links_mitigations_mitre:
        print(links_mitigations_mitre)
    else:
        print(f'No mitigations for {cve}')
time_stop = "Программа отработала за %s секунд" % (time.time() - start_time)
print(time_stop)
'''
