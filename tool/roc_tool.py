#coding:utf-8
__author__ = 'jmh081701'
#主要负责绘制roc曲线
import  json
from matplotlib import  pyplot as plt
import  numpy as np
from sklearn.metrics import *
def roc(real,pre):
    fp,tp,thres=roc_curve(real,pre)
    return fp,tp,thres