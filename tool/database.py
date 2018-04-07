#coding:utf-8
__author__ = 'jmh081701'
from pymongo import *
import json
import  time
import  random
class dat_filetool:
    def __init__(self,dat_filename):
        '''
        :param dat_filename: *.dat 文件,由c++生成原始样本数据
        :return:
        '''
        try:
            self.fp = open(dat_filename,"r")
        except:
            raise "open %s fail!"%dat_filename
    def reader(self):
        rst=list()
        lines=self.fp.readlines()
        for each in lines:
            each =each.split(sep=' ')
            sample={'label':'0','vec':[]}
            sample['label']='nat' if int(each[0])==2 else 'host'
            for i in range(1,len(each)):
                if(i in [15]):
                    continue
                    #过滤diff udp-tcp 没有区分度
                sample['vec'].append(float(each[i]))
            rst.append(sample.copy())
        self.fp.close()
        return rst
class DataBase:
    def __init__(self,username="jmh",pwd="123456",ip="127.0.0.0",dbname="feature",port="27017"):
        self.client =MongoClient("mongodb://%s:%s@%s:%s/%s"%(username,pwd,ip,port,dbname))
        self.db=self.client[dbname]
        self.dataset=self.db['nat_dataset']
    def insert(self,samples):
        if type(samples)!=type([{'label':'1','vec':[0,1]}]):
            samples=[samples]
        for each in samples:
            if 'label' not in each:
                raise 'sample donot has label key-value.'
            if 'vec' not in each:
                raise 'sample donot has vec key-value.'
            if type(each['vec'])!=type([0,1,2,3]):
                raise 'vec donot map to a list'
            each['timestamp']=time.strftime("%Y-%m-%d %H:%M:%S")
            #print(each['timestamp'])
            self.dataset.insert(each)
    def get_dataset(self,cond={}):
        rst=list()
        datas=self.dataset.find(cond)
        for each in datas:
            rst.append(each)
        return  rst
    def delete(self,cond):
        self.dataset.delete_many(cond)
    def data_clean(self):
        #数据清洗,把一些明显标注错误的样本删除或者修正过来
        data=self.get_dataset()

        for each in data:
            if each['label']=='host' and each['vec'][-2]>1:
                    self.delete(cond={'_id':each['_id']})
                    sample={}
                    sample.setdefault('label','nat')
                    sample.setdefault('vec',each['vec'])
                    sample.setdefault('timestamp',each['timestamp'])
                    self.insert(sample)
    def data_augmentation(self):
        #数据集增强,主要通过计算正负样本的均值，方差，向正负样本加上高斯噪声
        #高斯噪声

        label="host"
        data=self.get_dataset(cond={'label':label})
        avg=list()
        std=list()
        veclen=len(data[0]['vec'])
        sampleSize=len(data)
        for j in range(0,veclen):
            avg.append(0)
            for i in range(0,sampleSize):
                avg[j]+=data[i]['vec'][j]
        for  j in range(0,veclen):
            avg[j]/=sampleSize

        for j in range(0,veclen):
            std.append(0)
            for i in range(0,sampleSize):
                std[j]+=(data[i]['vec'][j]-avg[j])**2

        for j in range(0,veclen):
            std[j]/=(0.000001+sampleSize-1)
            std[j]=std[j]**0.5+0.000001
        for each in data:
            for j in range(0,veclen):
                #each['vec'][j]=(each['vec'][j]-avg[j])/std[j]
                each['vec'][j]=0.95*each['vec'][j]+0.05*random.gauss(avg[j],std[j])
            each.setdefault('tag','data_augmentation')
            each.pop('_id')
        self.insert(data)




        label="nat"
        data=self.get_dataset(cond={'label':label})
        nat_data=data.copy()
        avg=[]
        std=[]
        veclen=len(data[0]['vec'])
        sampleSize=len(data)
        for j in range(0,veclen):
            avg.append(0)
            for i in range(0,sampleSize):
                avg[j]+=data[i]['vec'][j]
        for  j in range(0,veclen):
            avg[j]/=sampleSize

        for j in range(0,veclen):
            std.append(0)
            for i in range(0,sampleSize):
                std[j]+=(data[i]['vec'][j]-avg[j])**2

        for j in range(0,veclen):
            std[j]/=(0.000001+sampleSize-1)
            std[j]=std[j]**0.5+0.000001
        for each in data:
            for j in range(0,veclen):
                #each['vec'][j]=(each['vec'][j]-avg[j])/std[j]
                each['vec'][j]=0.95*each['vec'][j]+0.05*random.gauss(avg[j],std[j])
            each.setdefault('tag','data_augmentation_gauss')
            each.pop('_id')
        self.insert(data)
        #将部分Nat的TTL个数改为1，因为也的确会有同一个局域网中所有主机的OS会是一致的情况.将比例控制在10%
        for each in nat_data:
            p=random.uniform(0,1)
            if p<0.1 and each['vec'][-2]!=1:
                each['vec'][-2]=1
                each.setdefault('tag','data_augmentation_nat_synthes')
                each.pop('_id')
                self.insert(each)
if __name__ == '__main__':
    filereader= dat_filetool("./data/vectorize_data_04_01_mirror.dat")
    dataset=filereader.reader()
    db=DataBase(ip="127.0.0.1")
    db.insert(dataset)

