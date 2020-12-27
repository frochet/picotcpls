truncate -s 60M test_multipath.data
./../../cli -t -f bpf_cubic.o -T simple_transfer -i test_multipath.data -k ../assets/server.key -c ../assets/server.crt -Z fc00:0:3::2 192.168.3.100 4443

