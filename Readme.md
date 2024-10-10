## AutoPatch

​	自动patch shellcode到PE文件的脚本

### 原理

​	使用IDA的startup签名自动识别PE入口点（WinMain/Main）后将shellcode覆盖过去，并简单处理重定位表保证shellcode的运行

### 使用

​	`usage: autoPatch.py [-h] pe_file_path shellcode_path`

​	
