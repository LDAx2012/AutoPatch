## AutoPatch

​	自动patch shellcode到PE文件的脚本

### 原理

​	使用IDA的startup签名自动识别PE入口点（WinMain/Main），后将shellcode覆盖过去

