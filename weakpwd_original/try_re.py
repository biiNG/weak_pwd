import re
url = "http://www.baidu.com/"
url_path= ''
for i in re.findall(".*?/",url):
    print(i)
    url_path = url_path+i
    print(url_path)