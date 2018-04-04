__author__ = 'dell'
import  define
import  socket
from PREDICT_WITH_DATAFLOW import  Predict
address=(define.PHOST,define.PPORT)
server_py=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
server_py.bind(address)
server_c=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
server_c.connect((define.CHOST,define.CPORT))

if __name__ == '__main__':
    #预测时的主函数
    print("bind well")
    cnnmodel=Predict(modeldir="./")
    while True:
        data,addr=server_py.recvfrom(4096)
        if not data:
            print("client has exist")
            break
        #print("data",data)
        datas=data.decode(encoding='utf8').split(';') #最后一个不需要
        #print("receivce %d sample."%len(datas[0:-1]))
        out=cnnmodel.predict(datas)
        print(out)
        #计算
        #发送结果
        server_c.send(bytes(out,encoding='utf8'))

