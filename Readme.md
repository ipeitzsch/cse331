# Hail Mary CSE331 Project 1
## Authors
Ian Peitzsch, Mathews Thankachan, Xinhang Xie
## About
This project is a rootkit in the form of a loadable kernel module for Linux Kernel version 2.6.38.8 and has been tested on Ubuntu 11.04 32-bit version. This rookit assumes the attacker has already managed to gain root access to computer. Once loaded, the rootkit does the following tasks:

- Hides specific files and directories from showing up when a user does `ls` and similar commands 
- Modifies the /etc/passwd and /etc/shadow file to add a backdoor account while returning the original contents of the files (pre-attack) when a normal user requests to see the file
- Hides specific processes from the process table when a user does a `ps`
- Give the ability to a malicious process to elevate its uid to 0 (root) upon demand 
