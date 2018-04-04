#coding:utf-8
__author__ = 'jmh081701'
from BaseTool import  *
import  tensorflow as tf
import math
import json

'''
The input vector should be a shape of [InputColumn,?]
'''
dataset=None
#dataset=dat_filetool("./data/vectorize_data_03_30_mirror.dat").reader()
data=Preprocess(List=dataset)
InputColumn=18
InputRow=int(data.veclen/InputColumn)
InputX=tf.placeholder(dtype=tf.float32,shape=[None,None],name="InputX")
InputY=tf.placeholder(dtype=tf.float32,shape=[None,2],name="InputY")

dir="./"

writer=tf.summary.FileWriter(dir+".//cnngrahph",tf.get_default_graph())
merged=tf.summary.merge_all()

'''
    Saver:模型保存器
'''

with tf.name_scope('L1'):
    W_C1=tf.Variable(tf.truncated_normal([InputColumn,32],stddev=0.01),dtype=tf.float32)
    b_C1=tf.Variable(tf.constant(0.1,tf.float32,shape=[32]))

    X=tf.reshape(InputX,[-1,InputColumn])

    featureMap_C1=tf.matmul(X,W_C1,name="L1MatMul")+b_C1


with tf.name_scope('Active1'):
    relu_C1=tf.nn.relu(featureMap_C1)  #激活层

with tf.name_scope('L2'):
    W_C2=tf.Variable(tf.truncated_normal([32,64],stddev=0.01))
    b_C2=tf.Variable(tf.constant(0.1,tf.float32,shape=[64]))
    featureMap_C2=tf.matmul(relu_C1,W_C2,name="L2MatMul")+b_C2
with tf.name_scope('Active2'):
    relu_C2=tf.nn.relu(featureMap_C2)

with tf.name_scope('L3'):
    W_C3=tf.Variable(tf.truncated_normal([64,256],stddev=0.01))
    b_C3=tf.Variable(tf.constant(0.1,tf.float32,shape=[256]))
    featureMap_C3=tf.matmul(relu_C2,W_C3,name="L3MatMul")+b_C3
with tf.name_scope('Active3'):
    relu_C3=tf.nn.relu(featureMap_C3)

with tf.name_scope('L4'):
    W_C4=tf.Variable(tf.truncated_normal([256,512],stddev=0.01))
    b_C4=tf.Variable(tf.constant(0.1,tf.float32,shape=[512]))
    featureMap_C4=tf.matmul(relu_C3,W_C4,name="L4MatMul")+b_C4
with tf.name_scope('Active4'):
    relu_C4=tf.nn.relu(featureMap_C4)

with tf.name_scope('L5'):
    W_C5=tf.Variable(tf.truncated_normal([512,1024],stddev=0.01))
    b_C5=tf.Variable(tf.constant(0.1,tf.float32,shape=[1024]))
    featureMap_C5=tf.matmul(relu_C4,W_C5,name="L5MatMul")+b_C5
with tf.name_scope('Active5'):
    relu_C5=tf.nn.relu(featureMap_C5)

with tf.name_scope('L6'):
    W_C6=tf.Variable(tf.truncated_normal([1024,2048],stddev=0.01))
    b_C6=tf.Variable(tf.constant(0.1,tf.float32,shape=[2048]))
    featureMap_C6=tf.matmul(relu_C5,W_C6,name="L6MatMul")+b_C6
with tf.name_scope('Active6'):
    relu_C6=tf.nn.relu(featureMap_C6)
with tf.name_scope('L7'):
    W_C7=tf.Variable(tf.truncated_normal([2048,1024],stddev=0.01))
    b_C7=tf.Variable(tf.constant(0.1,tf.float32,shape=[1024]))
    featureMap_C7=tf.matmul(relu_C6,W_C7,name="L7MatMul")+b_C7
with tf.name_scope('Active7'):
    relu_C7=tf.nn.relu(featureMap_C7)

#全连接层完成
with tf.name_scope('output'):
    W_OUTPUT=tf.Variable(tf.truncated_normal([1024,2],stddev=0.01))
    b_OUTPUT=tf.Variable(tf.constant(0.1,tf.float32,shape=[2]))
    predictY=tf.nn.softmax(tf.matmul(relu_C7,W_OUTPUT)+b_OUTPUT,name="predictY")
outputY=tf.add(predictY,0,name="outputY")
#输出层,使用softmax函数

loss=tf.reduce_mean(-tf.reduce_sum(InputY*tf.log(predictY)))
#tf.summary.histogram('loss',loss)
tf.summary.scalar('loss',loss)
#残差函数loss设置为交叉熵
learning_rate=1e-5
#train_op=tf.train.AdamOptimizer(learning_rate).minimize(loss)
train_op=tf.train.AdamOptimizer(learning_rate).minimize(loss)

y_pred=tf.arg_max(predictY,1)
bool_pred=tf.equal(tf.arg_max(InputY,1),y_pred)
right_rate=tf.reduce_mean(tf.to_float(bool_pred))
tf.summary.scalar("right rate",right_rate)
Saver=tf.train.Saver()


def load_model(sess,modelname="cnnmodel"):
    ckpt=tf.train.get_checkpoint_state(dir)
    if ckpt and ckpt.model_checkpoint_path:
        print("*"*30)
        print("load lastest model......")
        Saver.restore(sess,dir+modelname)
        print("*"*30)

def save_model(sess,modelname="cnnmodel"):
    print("*"*30)
    Saver.save(sess,dir+modelname)
    print("saving model well.")
    print("*"*30)
merge_op=None
merge_op2=None
with tf.Session() as sess:
    init =tf.global_variables_initializer()
    sess.run(init)

    step=1
    sameMAX=40
    sameStep=0
    accSum=0
    batch_epoch=int(data.num_example()/30)
    load_model(sess)
    while True:
        if(step%batch_epoch==0):
            #测试一下
            test_vec,test_lab=data.next_test_batch(batchSize=30)
            tf.summary.scalar('valid:rate',right_rate)

            if merge_op2==None:
                merge_op2=tf.summary.merge_all()
            acc,summary_=sess.run([right_rate,merge_op2],{InputX:test_vec,InputY:test_lab})
            writer.add_summary(summary_,step)
            print({"!!!!!!!!!!!!!!testing:"+str(step):acc})
            accSum=accSum+acc
            sameStep+=1
            if(sameStep%sameMAX==0):
                if(acc==accSum/sameMAX):
                    print({step:acc})
                    break
                else:
                    accSum=0
                    sameStep=0
                save_model(sess)
            step=step+1
            continue
        train_vec,train_lab=data.next_train_batch(batchSize=50)
        if merge_op==None:
            merge_op=tf.summary.merge_all()
        l,op,summary=sess.run([loss,train_op,merge_op],feed_dict={InputX:train_vec,InputY:train_lab})
        #py,l,op=sess.run([predictY,loss,train_op])
        print(step,l)
        if(step%20==0):
            #每隔20批,跟踪一次
            writer.add_summary(summary,step)
            pass
        step=step+1
    save_model(sess)
    #print(data.test_vectors())
    print(sess.run([right_rate],feed_dict={InputX:data.test_vectors(),InputY:data.test_labels()}))
#注意点！在随机化参数的时候,不能标准差不能太大，否则很容易在计算log时出现nan