# Cwebscan_-python3

老旧版本的Cwebscan使用的是python2.x,用起来一堆bug,更新一下适配python3.x

使用前请运行下面命令安装好依赖
pip install IPy gevent requests dnspython beautifulsoup4 lxml

通用命令：
python Cwebscan.py 目标参数 [-t 线程数] [-p 自定义端口]
