#coding:utf-8
__author__ = 'jmh081701'
import  json
from matplotlib import  pyplot as plt
import  numpy as np
with open(r"data.file") as fp:
    ipid_sequences=json.load(fp)
color=['r','black','b','g','q']
for i in range(len(ipid_sequences)):
    each=ipid_sequences[i]
    print(len(each))
    each=np.array(each)
    plt.scatter(each[:,1],each[:,0],marker="+")
plt.xlabel("relative arrive time(s)")
plt.ylabel("tcp source port (1)")
plt.ylim(1024,70000)

plt.show()
exit(0)
'''
with open("..\\CaptureEstimator\\CaptureEstimator\\sample_entropy.data") as fp:
    sample_entroy=json.load(fp)

with open("..\\CaptureEstimator\\CaptureEstimator\\benchmark_entropy.data") as fp:
    benchmark=json.load(fp)
x=[]
y=[]
for i in  range(len(benchmark)-1):
    x.append(i)
    y.append(abs(sample_entroy[i]-benchmark[i]))
#plt.plot(x,sample_entroy,label="sample entropy")
#plt.plot(x,benchmark,label="benchmark entropy")
plt.subplot(2,1,1)
plt.plot(x,y,label="abs(sample entropy-benchmark)")
plt.legend(loc="upper center")

plt.subplot(2,1,2)
plt.hist(y,bins=256,histtype="barstacked",label="histogram")

plt.show()
'''