#/bin/sh

gcc ./*.c -o a.out -lpcap
sudo ./a.out 
rm ./a.out
