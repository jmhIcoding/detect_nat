#coding:utf8
__author__ = 'jmh081701'
import  tensorflow as tf
import  numpy as np
import  json
import  time
import random
from database import  dat_filetool
from  BaseTool import *
with open("normalize_parameter.data","r") as fp:
    normalize_parameter=json.load(fp)
raw_data=dat_filetool("./data/valid_data.dat").reader()
data=Preprocess(List=raw_data,SuperParameter=normalize_parameter)
dir ="./"
modelname="cnnmodel"
ckpt =tf.train.get_checkpoint_state(dir)
saver=object()
if ckpt and ckpt.model_checkpoint_path:
    print("*"*30)
    print("loading model........")
    saver=tf.train.import_meta_graph(ckpt.model_checkpoint_path+".meta",clear_devices=True)
    print("loaded well")
else:
    raise("model load fail ")


with tf.Session() as sess:
    saver.restore(sess,ckpt.model_checkpoint_path)
    while True:
        print("please input something : s")
        s=input()
        print(s)
        start=time.clock()
        vec=data.train_vectors().copy()
        lab=data.train_lables().copy()
        out=sess.run("outputY:0",feed_dict={"InputX:0":vec,"InputY:0":lab})
        #print(out)
        errorcnt=0
        for i in range(len(lab)):
            print("predict:%s, real:%s ."%(str(out[i]),str(lab[i])))
            if (out[i][0]>out[i][1]) != (lab[i][0]>lab[i][1]):
                errorcnt+=1
                print(vec[i])

                print(data.denormalize_minmax(vec[i],normalize_parameter))

        end=time.clock()
        print(end-start)
        print("error:%d / %d "%(errorcnt,len(lab)))