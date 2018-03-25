__author__ = 'jmh081701'
from database import  *
db=DataBase(ip="127.0.0.1")
#db.delete(cond={})
dataset=db.get_dataset()
print(dataset)

