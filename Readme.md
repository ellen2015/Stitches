# Stitches(缝合怪)

这个项目是集成了之前的一些Windows kernel开发代码，类似一个缝合怪项目所以取名为"Stitches"

目前的功能有
* APC 内核模式早鸟注入DLL (kernel apc injector(early bird mode))
* 内核日志实现（kernel log informations）
* 探针agent
  * 进程回调（进程上下文数据）
  * 线程回调（远程线程检测）
  * 映像回调（配合APC 早鸟注入hook dll监控目标进程api行为）
  * 对象回调（进程保护（防止被恶意程序结束进程） + lsass进程防止读取进程内存）
* MiniFilter
  * 文件保护
  * USB设备管控（待测试...）
* ...