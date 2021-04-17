import requests
from bs4 import BeautifulSoup as BS
import re

url = 'http://49.235.204.174/admin/'
request_header = {
    'User - Agent': 'Mozilla / 5.0(Windows NT 10.0;Win64;x64;rv: 71.0) Gecko / 20100101 Firefox / 71.0',
    'Accept': 'text / html, application / xhtml + xml, application / xml;q = 0.9, * / *;q = 0.8',
    'Accept - Language': 'zh - CN, zh;q = 0.8, en;q = 0.2',
    'Accept - Encoding': 'gzip',
}
r = requests.get(url, headers=request_header)

soup = BS(r.text,'lxml')
# print(soup)
verify_codes=['验证码','点击更换','点击刷新','checkcode','valicode','code','captcha']
result = re.findall(".*<form(.*)</form>",r.text,re.S)
# print(r.text)
# print(result)
if result:
    form_data = '<form ' + result[0] + '</form>'
    form_soup = BS(form_data, 'lxml')
    form = form_soup.form
    print(form.find_all('input'))