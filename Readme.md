# Stitches(缝合怪)

这个项目是集成了之前的一些Windows kernel开发代码，类似一个缝合怪项目所以取名为"Stitches"

目前的功能有
* APC 内核模式早鸟注入DLL (kernel apc injector(early bird mode))
* 内核日志实现（kernel log informations）
* 探针agent
  * 进程回调（进程上下文信息）
  * 线程回调（远程线程检测）
  * 映像回调（dll监控配合APC 早鸟注入）
  * 对象回调（进程保护 + 防止读取lsass进程），需要你设置自己的Altitude值
* 文件保护（Using minifilter to protect target file or directory）
* USB设备管控（待测试...）
* ...