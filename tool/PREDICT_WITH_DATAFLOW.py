#coding:utf-8
__author__ = 'jmh081701'
import  tensorflow as tf
import  numpy as np
import  json    # 使用ujson会快很多,import ujson as json
class Predict(object):
    def __init__(self,modeldir):
        dir =modeldir
        self.ckpt =tf.train.get_checkpoint_state(dir)
        self.saver=object()
        if self.ckpt and self.ckpt.model_checkpoint_path:
            print("*"*30)
            print("loading model........")
            self.saver=tf.train.import_meta_graph(self.ckpt.model_checkpoint_path+".meta",clear_devices=True)
            print("loaded well")
        else:
            raise Exception("model load fail ")
            exit(-1)
        with open(dir+"normalize_parameter.data","r") as fp:
            self.normalize_parameter=json.load(fp)
        self.explen=len(self.normalize_parameter[0])
        self.sess=tf.Session()
        self.saver.restore(self.sess,self.ckpt.model_checkpoint_path)
        self.defaultVec=np.zeros(shape=[1,self.explen])
        self.min=self.normalize_parameter[0]
        self.max=self.normalize_parameter[1]

    def __PADDING(self,vector):
        rst=vector
        while(len(rst)<self.explen):
            rst.append(0.0)
        return rst

    def normalize_minmax(self,vec,normalize_parameter):
        #归一化
        min=normalize_parameter[0]
        max=normalize_parameter[1]
        for j in range(0,len(vec)):
            vec[j]=(vec[j]-min[j])/(max[j]+min[j]+0.000001)
            if (vec[j]>1e3):
                print(vec)
                raise "Error input vector."
        return vec
    def vectorize(self,List):
        rst=list()
        vec=list()
        lab=list()

        for eachLine in List:
            #print(eachLine)
            line=eachLine.split(sep=" ")
            sample={'ip':"192.168.1.1",'label':'0','vec':[]}
            sample['label']=line[1]
            sample['ip']=line[0]
            for i in range(2,len(line)):
                if i in [16]:
                    continue
                    #过滤 diff udp-tcp 因为区分度
                sample['vec'].append(float(line[i]))
            sample['vec']=self.normalize_minmax(sample['vec'],self.normalize_parameter)
            vec.append(sample['vec'].copy())
            lab.append([0.,0.])
            sample['vec']=None
            rst.append(sample.copy())
        return rst,vec,lab

    def predict(self,inputList):
        try:
            #print(inputList)
            info,vec,lab=self.vectorize(inputList[0:-1])
            out=self.sess.run("outputY:0",feed_dict={"InputX:0":vec,"InputY:0":lab})
            outstring =""
            for i in range(0,len(info)):
                outstring+=info[i]['ip']+" "+str( out[i][1])+";"
            return outstring
        except:
            raise Exception("Error input List.")
if __name__ == '__main__':
    cnnmodel = Predict(modeldir="./")
    inputList="192.168.1.1 2 51691 77924749 50641 4770915 84444 100244 1651 640 2963 576 1515 653 2.000000 720.000000 0.002782 0.963462 0 2 14823.428863;192.168.30.34 2 115585 185072803 88677 5977789 178816 202565 1688 611 1925 605 1407 319 -1.000000 720.000000 -0.001391 0.983428 0 3 23074.247645;"
    inputList=inputList.split(';')
    out=cnnmodel.predict(inputList)
    print(out)
