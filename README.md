# cs_beacon_download

自实现beacon下载器

下载器原理就是访问cs的stager下载stageless Beacon

通过get请求cs的porfile文件中的http-stager中x86或x64的url

下载后跳过配置文件前面追加字符, 然后执行cc，这里与加载器的区别就是这里的内存是rwx, 加载器可rx

在cmd中执行编译生成的exe，传入大于1的参数执行

code2强力免杀
