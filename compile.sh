#!/bin/bash

gcc firewall.c -o firewall -lpthread

cp firewall /tmp/pycore.44965/firewall.conf/firewall

#cp server.sh /tmp/pycore.36001/n4.conf/server.sh
#chmod u+x /tmp/pycore.36001/n4.conf/server.sh

#cp client.sh /tmp/pycore.36001/n3.conf/client.sh
#chmod u+x /tmp/pycore.36001/n3.conf/client.sh