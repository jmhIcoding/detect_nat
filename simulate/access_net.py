__author__ = 'dell'
import requests
import random
import time
urllist=[
    "http://www.baidu.com",
    "http://www.qq.com"
]
s=[["ipid","timestamp"]]
s="iloveyou"
s.find("love")
s.__str__()

while True:
    i =random.randint(0,len(urllist)-1)
    req=requests.get(urllist[i])
    print(req.content)
    time.sleep(random.randint(0,10))
    req.close()

