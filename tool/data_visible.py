#coding:utf-8
__author__ = 'jmh081701'
import  json
from matplotlib import  pyplot as plt
import  numpy as np
from roc_tool import  roc
with open(r"p2pmlproc_file") as fp:
    _real,_pre=json.load(fp)
real=[]
pre=[]
for i in range(len(_pre)):
    real.append(1-float(_real[i]))
    pre.append(1-float(_pre[i]))

fpre2,tpre2,thres=roc(real,pre)

with open(r"p2pcnnroc_file") as fp:
    _real,_pre=json.load(fp)
real=[]
pre=[]
for i in range(len(_pre)):
    real.append(1-float(_real[i]))
    pre.append(1-float(_pre[i]))

fpre3,tpre3,thres=roc(real,pre)

'''
with open(r"激活函数sigmoidroc_file") as fp:
    _real,_pre=json.load(fp)
real=[]
pre=[]
for i in range(len(_pre)):
    real.append(float(_real[i]))
    pre.append(float(_pre[i]))

fpre4,tpre4,thres=roc(real,pre)


with open(r"隐层个数5roc_file") as fp:
    _real,_pre=json.load(fp)
real=[]
pre=[]
for i in range(len(_pre)):
    real.append(float(_real[i]))
    pre.append(float(_pre[i]))

fpre5,tpre5,thres=roc(real,pre)

with open(r"隐层个数6roc_file") as fp:
    _real,_pre=json.load(fp)
real=[]
pre=[]
for i in range(len(_pre)):
    real.append(float(_real[i]))
    pre.append(float(_pre[i]))

fpre6,tpre6,thres=roc(real,pre)

with open(r"隐层个数7roc_file") as fp:
    _real,_pre=json.load(fp)
real=[]
pre=[]
for i in range(len(_pre)):
    real.append(float(_real[i]))
    pre.append(float(_pre[i]))

fpre7,tpre7,thres=roc(real,pre)
'''
plt.plot(fpre2,tpre2,"-.b",label=u"mlp",markersize=3)
plt.plot(fpre3,tpre3,"-.g",label=u"cnn",markersize=3)
#plt.plot(fpre4,tpre4,"-.b",label=u"sigmoid",markersize=3)
#plt.plot(fpre5,tpre5,"--k",label=u"layer number:5",markersize=3)
#plt.plot(fpre6,tpre6,"*m",label=u"layer number:6",markersize=3)
#plt.plot(fpre7,tpre7,"xc",label=u"layer number:7",markersize=3)
plt.xlabel("fpr")
plt.ylabel("tpr")
plt.title("roc curve corresponding with Model")
wide=1
plt.xlim(0,wide)
plt.ylim(1-wide,1)
plt.legend()
plt.show()
exit(0)
