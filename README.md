# database-firewall
基于机器学习的数据库防火墙，主要且唯一的功能是防止sql注入

data文件夹存放的是sql语句，用于训练模型
model文件夹存放的是训练好的模型，可以删除文件夹下的模型，代码会根据data里面的语句重新训练并保存

防火墙的代理功能是参照nim4的DBShield，项目详情见https://github.com/nim4/DBShield

防止sql注入的机器学习算法是参考了http://nbviewer.jupyter.org/github/ClickSecurity/data_hacking/blob/master/sql_injection/sql_injection.ipynb
