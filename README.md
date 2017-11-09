# database-firewall
基于机器学习的数据库防火墙，主要且唯一的功能是防止sql注入。使用的时候将原本向mysql数据库请求的端口（默认是3306）改成防火墙的端口（默认是5000）即可。

data文件夹存放的是sql语句，用于训练模型
model文件夹存放的是训练好的模型，可以删除文件夹下的模型，代码会根据data里面的语句重新训练并保存
log文件夹存放的是log文件
assets文件夹存放的是实时显示sql语句数目的web界面相关的html、css和javascript文件

config.ini是配置文件，相关参数可以在上面更改

防火墙的代理功能是参照nim4的DBShield，项目详情见https://github.com/nim4/DBShield

防止sql注入的机器学习算法是参考了http://nbviewer.jupyter.org/github/ClickSecurity/data_hacking/blob/master/sql_injection/sql_injection.ipynb

这个项目纯粹属于练手之用，不足之处敬请谅解
