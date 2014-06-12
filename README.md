# olrunner, the libsandbox frontend for OpenOlympus

##Usage

```
olrunner [options] -- command
```

Options: 

* memorylimit - If the child program's memory usage peaks past this limit, it will get killed.
* cpulimit - The maximum amount of CPU time in milliseconds that the child program can use before it is killed.
* timelimit - The maximum amount of real time in milliseconds that the child program can use before it is killed.
* disklimit - The maximum amount of bytes that the child program can read and write before it is killed.
* security - If set to one, ptrace will be used to filter out syscalls.If set to zero, libsandbox will not filter syscalls.
* jail - The path to the location of the chroot not-quite-jail. Must contain the required directories and libraries.

Warning: chrooting requires root priviliges!

Example:

```
sudo olrunner --memorylimit=1073741824 --cpulimit=10000 --timelimit=10000 --disklimit=1073741824 --security=1 --jail=/tmp/olrunnerchroot -- ./a.out hello
```

##Installation
```
cmake -G "Unix Makefiles"
make all
sudo make install
```