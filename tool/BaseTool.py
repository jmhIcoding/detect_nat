#coding:utf-8
__author__ = 'jmh081701'
import numpy as np
import random
import  tensorflow as tf
import  random
from database import  DataBase
from database import  dat_filetool
class Preprocess:
    db=None
    def __init__(self,label=None,rate=0.3,List=None):
        self.label=label
        self.rate=rate
        if List==None:
            Preprocess.db=DataBase()
            self.List=Preprocess.db.get_dataset({})
        else:
            self.List=List
        self.__train=[[],[]]
        self.__test=[[],[]]
        self.__possSimpleind=[]#正样本下标
        self.__vectors()
        self.__labels()
        self.count=0
        self.veclen=len(self.vec[0])
        self.randomize()

    def randomize(self):
        length =self.num_example()
        self.__test[0]=[]
        self.__test[1]=[]
        self.__train[0]=[]
        self.__train[1]=[]
        testAmount =int(length*self.rate)
        possAmt=int(len(self.__possSimpleind)*self.rate)
        testind=[]
        for i in range(0,possAmt):
            testind.append(self.__possSimpleind[random.randint(0,len(self.__possSimpleind)-1)])
        for i in range(possAmt,testAmount):
            rnd=random.randint(0,length)
            if(rnd not in testind):
                testind.append(rnd)

        for i in range(0,length):
            if i in testind:
                self.__test[0].append(self.vec[i])
                self.__test[1].append(self.lab[i])
            else:
                self.__train[0].append(self.vec[i])
                self.__train[1].append(self.lab[i])

    def read_data(self):
        pass
    def next_train_batch(self,batchSize=100):
        self.count+=1
        #if self.count%30==0:
        #    self.randomize()
        ind=[]
        vec=[]
        lab=[]
        while(len(ind)<min(batchSize,len(self.__train[1]))):

            index=random.randint(0,len(self.__train[1])-1)
            if(index in ind):
                continue
            ind.append(index)
            v=self.__train[0][index]
            l=self.__train[1][index]

            vec.append(v)
            lab.append(l)
        return vec,lab

    def next_test_batch(self,batchSize=100):
        self.count+=1
        #if self.count%30==0:
        #    self.randomize()
        ind=[]
        vec=[]
        lab=[]
        while(len(ind)<min(batchSize,len(self.__test[1]))):
            index=random.randint(0,len(self.__test[1])-1)
            if(index in ind):
                continue
            ind.append(index)
            v=self.__test[0][index]
            l=self.__test[1][index]
            vec.append(v)
            lab.append(l)

        return vec,lab

    def __vectors(self):
        self.vec=[]
        self.avg=[]
        self.std=[]
        self.min=[]
        self.max=[]

        veclen=len(self.List[0]['vec'])
        sampleSize=len(self.List)
        '''
        for j in range(0,veclen):
            self.avg.append(0)
            for i in range(0,sampleSize):
                self.avg[j]+=self.List[i]['vec'][j]
        for  j in range(0,veclen):
            self.avg[j]/=veclen

        for j in range(0,veclen):
            self.std.append(0)
            for i in range(0,sampleSize):
                self.std[j]+=(self.List[i]['vec'][j]-self.avg[j])**2

        for j in range(0,veclen):
            self.std[j]/=veclen
            self.std[j]=self.std[j]**0.5+0.000001
        for each in self.List:
            each=each['vec']
            for j in range(0,veclen):
                each[j]=(each[j]-self.avg[j])/self.std[j]
            self.vec.append(each)
        '''
        for j in range(0,veclen):
            self.min.append(1e12)
            self.max.append(-1e12)
            for i in range(0,sampleSize):
                if self.List[i]['vec'][j]<self.min[j]:
                    self.min[j]=self.List[i]['vec'][j]
                if self.List[i]['vec'][j]>self.max[j]:
                    self.max[j]=self.List[i]['vec'][j]
        for each in self.List:
            each=each['vec']
            for j in range(0,veclen):
                each[j]=(each[j]-self.min[j])/(self.max[j]+self.min[j]+0.000001)
            self.vec.append(each)
        return self.vec

    def __labels(self):
        self.lab=[]
        i=0
        for each in self.List:
            l=each["label"]
            if(l=='nat'):
                self.__possSimpleind.append(i) #正样本
                self.lab.append([0.,1.])
            elif(l=='host'):
                self.lab.append([1.0,0.0])
            i+=1
        return self.lab

    def num_example(self):
        return  len(self.vec)

    def train_vectors(self):
        return self.__train[0]

    def test_vectors(self):
        return  self.__test[0]

    def train_lables(self):
        return self.__train[1]

    def test_labels(self):
        return self.__test[1]

    def debug(self):
        pass
        l=self.num_example()
        for i in range(0,l):
            if self.lab[i]==[0.,1.0]:
                if not 1.0 in self.vec[i]:
                    print(self.List[i])

if __name__ == '__main__':
    dataset=dat_filetool("vectorize_data.dat").reader()
    pre=Preprocess(List=dataset)
    #pre.debug()
    vec,label=pre.next_train_batch()
    #i=0
    print(vec)
    print(label)
