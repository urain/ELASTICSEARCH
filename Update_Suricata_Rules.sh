sudo rm -f /data/suricata/emerging.rules.tar.gz
sudo rm -rf /data/suricata/rules
wget https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz
sudo tar -zxvf emerging.rules.tar.gz -C /data/suricata/
rm -f emerging.rules.tar.gz
sudo docker exec -it suricata /bin/bash -c 'cp -r /data/suricata/rules/* /etc/suricata/rules'
sudo docker exec -it suricata /bin/bash -c 'cd /etc/suricata/rules && ls -lisa'
