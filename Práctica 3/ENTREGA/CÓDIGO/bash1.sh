#!/bin/bash


echo "Calculando los porcentajes de paquetes IP y no IP"
tshark -r traza.pcap -T fields -e eth.type>eth_type.txt
awk -v var1=`grep '0800' eth_type.txt | wc -l` -v var2=`grep '8100' eth_type.txt | wc -l` -v var3=`wc -l <eth_type.txt` 'BEGIN{print "Porcentaje IP: " (var1+var2)/var3*100, "%" }'
awk -v var1=`grep '0800' eth_type.txt | wc -l` -v var2=`grep '8100' eth_type.txt | wc -l` -v var3=`wc -l <eth_type.txt` 'BEGIN{print "Porcentaje NO IP: "100- (var1+var2)/var3*100, "%" }'

awk 'BEGIN{print "Paquetes IP:"}'
tshark -r traza.pcap -T fields -e ip.proto>protocol.txt
awk -v var1=`grep '6' protocol.txt | wc -l` -v var2=`wc -l <protocol.txt` 'BEGIN{print "\tPorcentaje TCP: " (var1/var2)*100, "%" }'
awk -v var1=`grep '17' protocol.txt | wc -l` -v var2=`wc -l <protocol.txt` 'BEGIN{print "\tPorcentaje UDP: " (var1/var2)*100, "%" }'
awk -v var1=`grep '6' protocol.txt | wc -l` -v var2=`grep '17' protocol.txt | wc -l` -v var3=`wc -l <protocol.txt` 'BEGIN{print "\tPorcentaje OTROS: " 100-((var1+var2)/var3)*100, "%" }'
