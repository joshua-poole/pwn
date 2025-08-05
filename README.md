# Linux Kernel Module Rootkit

<ins>__Important Disclaimer__</ins>: This repository is provided purely for educational and academic purposes. The software is provided "as is", and the author are not responsible for any damage, loss or harm that otherwise comes about from its use. This project is designed for educational use only and any attempts to use this code maliciously is illegal and may result in criminal prosecution. The author takes no liability for any harm done by, or attacks using, this code. In downloading or executing these files the user agrees to not hold the author liabile for any loss, damage or harm coming about as a result of this code.

This is designed to be malicious code. Do not run on your system!

I used a virtual machine running ubuntu 24.04 as a demonstration for this project.

This code was designed as part of a security course at UNSW, COMP6841, to understand and learn more about how rootkits
work under the hood. In this project, I use linux kernel modules, as a proof of concept of how easy it is to create
malicious code. I used ubuntu linux as a target system, but the concepts can just as easily be applied to other
operating systems like windows.

There will be attempts to obfuscate actions from users, which is a key characteristic of rootkits. This also makes them
*very* hard to detect and eliminate once a system has been infected.

Instructions for use:
1. Install a virtual machine to safeguard the host system from infection with malicious code - I used [this](https://www.youtube.com/watch?v=QXdFTEPXJ4M) tutorial to install Ubuntu 24.04 in VirtualBox
2. Once you have installed Ubuntu on the VM, clone the repo onto the VM with:
```git
$ git clone git@github.com:joshua-poole/something-awesome.git
```

3. Install the required linux headers
```shell
$ sudo apt install build-essential linux-headers-$(uname -r)
```

4. ***Important:*** ensure you change your network settings on the VM to be disabled, so the machine is not connected to the open internet

5. Run the following commands:
```shell
$ cd something-awesome/
$ make clean && make
$ sudo dmesg --clear
```
You will need to put in password for the VM in at this point.

6. Now, run the install command, and rootkit module should be installed in the kernel!
```shell
$ sudo insmod rootkitv2.ko
```


