__author__ = 'jmh081701'
from database import  *
db=DataBase(ip="127.0.0.1")
#db.delete(cond={})
#db.data_clean()
#db.data_augmentation()
dataset=db.get_dataset()
print(len(dataset))
#print(dataset)

