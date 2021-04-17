import urllib

import requests
from bs4 import BeautifulSoup as BS
import re

from weakpwd_original.weakpwd import log

url = 'http://49.235.204.174/admin/'
request_header = {
    'User - Agent': 'Mozilla / 5.0(Windows NT 10.0;Win64;x64;rv: 71.0) Gecko / 20100101 Firefox / 71.0',
    'Accept': 'text / html, application / xhtml + xml, application / xml;q = 0.9, * / *;q = 0.8',
    'Accept - Language': 'zh - CN, zh;q = 0.8, en;q = 0.2',
    'Accept - Encoding': 'gzip',
}
r = requests.get(url, headers=request_header)

soup = BS(r.text, 'lxml')
# print(soup)
verify_codes = ['验证码', '点击更换', '点击刷新', 'checkcode', 'valicode', 'code', 'captcha']
result = re.findall(".*<form(.*)</form>", r.text, re.S)
form_data = '<form ' + result[0] + '</form>'
form_soup = BS(form_data, 'lxml')
form = form_soup.form


def get_data(form):
    global id
    data = {}
    yzm = False
    id_name_list = ['name', 'id', 'account', 'username', 'id_username']
    for item in form.find_all('input'):
        for id_item in id_name_list:
            if item.has_attr(id_item):
                id = item[id_item]
                break
            else:
                id = ''

        if item.has_attr('value'):
            value = item['value']
        else:
            value = '000000'
        if id:
            for i in ['username', 'name', 'account', 'yonghu', 'id_username']:
                if i in id.lower():
                    value = '{user_name}'
            for i in ['password', 'pwd', 'mima', 'id_password']:
                if i in id.lower():
                    value = '{pass_word}'
            for i in ['checkcode', 'valicode', 'code', 'captcha', 'yzm']:

                if id.lower() in i:
                    print(id)
                    yzm = True

            for i in ['pma_username', 'pma_password']:
                if id.lower() == i:
                    print("phpmyadmin possible:", url, '\n')
                    log.write("??? phpmyadmin possible::" + url + '\n')
                    return ""

            data[id] = str(value)

    print(data)
    if yzm:
        print("在URL{}中发现有{}！请稍后再试。\n".format(url, yzm))
        log.write("??  ||在" + url + "中发现有验证码," + "跳过")
        return ''
    else:
        return urllib.parse.urlencode(data)

print(get_data(form))