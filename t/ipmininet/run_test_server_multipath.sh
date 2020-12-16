truncate -s 60M test_multipath.data
./../../cli -t -T multipath -i test_multipath.data -k ../assets/server.key -c ../assets/server.crt -Z fc00:0:5::2 192.168.5.2 4443

