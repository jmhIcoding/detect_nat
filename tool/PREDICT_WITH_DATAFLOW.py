#coding:utf-8
__author__ = 'jmh081701'
import  tensorflow as tf
import  numpy as np
import  json    # 使用ujson会快很多,import ujson as json

class Predict(object):
    def __init__(self,modeldir):
        dir =modeldir+"/"
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

    def __PADDING(self,vector):
        rst=vector
        while(len(rst)<self.explen):
            rst.append(0.0)
        return rst

    def __vectorize(self,List):
        pass

    def predict(self,inputJson):
        try:
            pass
        except:
            raise Exception("Error input Json.")
