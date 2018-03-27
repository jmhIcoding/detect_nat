#coding:utf8
__author__ = 'jmh081701'
import  tensorflow as tf
import  numpy as np
import  json
import  time
import random
from database import  dat_filetool
from  BaseTool import *
raw_data=dat_filetool("valid.dat").reader()
data=Preprocess(List=raw_data)
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

vec,lab=data.next_test_batch(batchSize=30)
with tf.Session() as sess:
    saver.restore(sess,ckpt.model_checkpoint_path)
    start=time.clock()
    out=sess.run("outputY:0",feed_dict={"InputX:0":vec,"InputY:0":lab})
    #print(out)
    for i in range(len(lab)):
        print("predict:%s, real:%s ."%(str(out[i]),str(lab[i])))
    end=time.clock()
    print(end-start)