#coding:utf-8
__author__ = 'jmh081701'
from pymongo import *
import json
import  time
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
if __name__ == '__main__':
    filereader= dat_filetool("vectorize_data.dat")
    dataset=filereader.reader()
    db=DataBase(ip="127.0.0.1")
    db.insert(dataset)

