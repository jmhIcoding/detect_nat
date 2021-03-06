#coding:utf-8
__author__ = 'jmh081701'
from BaseTool import  *
import  tensorflow as tf
import math
import json

'''
The input vector should be a shape of [InputColumn,?]
'''
#dataset=dat_filetool("vectorize_data.dat").reader()
data=Preprocess()
InputColumn=6
InputRow=int(data.veclen/InputColumn)
InputX=tf.placeholder(dtype=tf.float32,shape=[None,None],name="InputX")
InputY=tf.placeholder(dtype=tf.float32,shape=[None,2],name="InputY")
#InputX,InputY=data.next_train_batch(30)
#InputX=tf.to_float(InputX)
#InputY=tf.to_float(InputY)
'''
    输入InputX是原始输入,其中InputX[i]表示第i个样本的特征向量。
    输入InputY是原始的label. InputY[i]表示第i个训练样本的期望label.
'''

dir="./"

writer=tf.summary.FileWriter(dir+".//cnngrahph",tf.get_default_graph())
merged=tf.summary.merge_all()

'''
    Saver:模型保存器
'''

with tf.name_scope('C1'):
    W_C1=tf.Variable(tf.truncated_normal([3,3,1,32],stddev=0.01),dtype=tf.float32)
    b_C1=tf.Variable(tf.constant(0.1,tf.float32,shape=[32]))
    #W_C1是C1层的权值矩阵,它也是卷积核，共有32个卷积核。
    # b_C1则是偏置
    X=tf.reshape(InputX,[-1,InputRow,InputColumn,1])
    #需要对输入转化为conv2d想要的格式
    featureMap_C1=tf.nn.conv2d(X,W_C1,[1,1,1,1],padding='SAME')+b_C1
    #conv2d的参数：
    #input:[图片个数,图片长，图片宽，图片的通道数]
    #filter:[滤波器长，滤波器宽，输入通道数，输出通道数]
    #stride:[1,1,1,1] 在四个轴上跳跃的大小
    #OK,C1卷积完成

with tf.name_scope('f'):
    relu_C1=tf.nn.relu(featureMap_C1)  #激活层
with tf.name_scope('S2'):
    featureMap_S2=tf.nn.max_pool(relu_C1,ksize=[1,2,2,1],strides=[1,2,2,1],padding='SAME')
    #S2的池化。
with tf.name_scope('C3'):
    W_C3=tf.Variable(tf.truncated_normal([3,3,32,64],stddev=0.01))
    b_C3=tf.Variable(tf.constant(0.1,tf.float32,shape=[64]))
    featureMap_C3=tf.nn.conv2d(featureMap_S2,W_C3,[1,1,1,1],padding='SAME')+b_C3

with tf.name_scope('f'):
    relu_C3=tf.nn.relu(featureMap_C3)
with tf.name_scope('S4'):
    featureMap_S4=tf.nn.max_pool(relu_C3,ksize=[1,2,2,1],strides=[1,2,2,1],padding='SAME')
#C3以及S4的过程
with tf.name_scope('flat'):
    per=int(math.ceil(InputColumn/4.0)*math.ceil(InputRow/4.0) *64)
    fetureMap_flatter=tf.reshape(featureMap_S4,[-1,per])
#栅格化
with tf.name_scope('fullcont'):
    W_F5=tf.Variable(tf.truncated_normal([int(fetureMap_flatter.shape[1]),512],stddev=0.1))
    b_F5=tf.Variable(tf.constant(0.1,tf.float32,shape=[512]))
    out_F5=tf.nn.relu(tf.matmul(fetureMap_flatter,W_F5)+b_F5)
    #out_F5_drop=tf.nn.dropout(out_F5,keep_prob)
#全连接层完成
with tf.name_scope('output'):
    W_OUTPUT=tf.Variable(tf.truncated_normal([512,2],stddev=0.01))
    b_OUTPUT=tf.Variable(tf.constant(0.1,tf.float32,shape=[2]))
    predictY=tf.nn.softmax(tf.matmul(out_F5,W_OUTPUT)+b_OUTPUT,name="predictY")
outputY=tf.add(predictY,0,name="outputY")
#输出层,使用softmax函数

loss=tf.reduce_mean(-tf.reduce_sum(InputY*tf.log(predictY)))
#tf.summary.histogram('loss',loss)
tf.summary.scalar('loss',loss)
#残差函数loss设置为交叉熵
learning_rate=1e-4
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
        train_vec,train_lab=data.next_train_batch(batchSize=200)
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