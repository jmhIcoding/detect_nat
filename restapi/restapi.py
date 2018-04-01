#coding:utf-8
__author__ = 'dell'
from  flask import  Flask
from  flask import jsonify
from flask import  request
app=Flask(__name__)
'''
request format:
{
    "ip1":[,,,],
    "ip2":[,,,],
    "ip3":[,,,]
}
向量是一个19维的向量
'''
@app.route("/api/predict",methods=["POST"])
def predicts():
    req=request.json
    print(req)
    for each in req:
        print(each)
        print(req[each])
    return jsonify({"status":"OK"})
app.run("0.0.0.0",port=9090)