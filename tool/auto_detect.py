#coding:utf-8
__author__ = 'jmh081701'
import time
import  os
import sys
def auto_detect(outfile,timegap,net):
    while True:
        print("scan.......")
        timestr=time.strftime("%H:%M:%S")
        cmd =os.popen("nmap -sn %s"%net)
        result=cmd.readlines()
        with open(outfile,"a") as fp:
            fp.writelines("*"*30)
            fp.writelines("\n")
            fp.writelines(timestr)
            fp.writelines(result)
        time.sleep(timegap)


if __name__ == '__main__':
    print(sys.argv)
    if len(sys.argv)!=4:
        print("usage: python auto_detect outfile timegap scannet")
        exit(-1)
    auto_detect(sys.argv[1],float(sys.argv[2]),sys.argv[3])



