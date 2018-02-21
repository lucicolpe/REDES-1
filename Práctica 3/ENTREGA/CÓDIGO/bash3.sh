#!/bin/bash

echo
echo

#tamanios nivel 2 destino
echo "Calculando tamanios nivel 2 destino"
tshark -r traza.pcap -T fields -e frame.len -Y 'eth.dst eq 00:11:88:CC:33:E1' | sort -n > tamanios_nivel_2_destino.txt
awk -v total=`wc -l <tamanios_nivel_2_destino.txt` '{ecdf+=1/total;print $1,ecdf}' tamanios_nivel_2_destino.txt > t_n_2_d_ecdf.txt

#tamanios nivel 2 origen
echo "Calculando tamanios nivel 2 origen"
tshark -r traza.pcap -T fields -e frame.len -Y 'eth.src eq 00:11:88:CC:33:E1' | sort -n > tamanios_nivel_2_origen.txt
awk -v total=`wc -l <tamanios_nivel_2_origen.txt` '{ecdf+=1/total;print $1,ecdf}' tamanios_nivel_2_origen.txt > t_n_2_o_ecdf.txt

#tamanios nivel 3 de paquetes HTTP destino
echo "Calculando tamanios nivel 3 de paquetes HTTP destino"
tshark -r traza.pcap -T fields -e ip.len -Y 'tcp.dstport eq 80' | sort -n >tamanios_HTTP_3_destino.txt
awk -v total=`wc -l <tamanios_HTTP_3_destino.txt` '{ecdf+=1/total;print $1,ecdf}' tamanios_HTTP_3_destino.txt > t_n_HTTPS_3_d_ecdf.txt

#tamanios nivel 3 de paquetes HTTP origen
echo "Calculando tamanios nivel 3 de paquetes HTTP origen"
tshark -r traza.pcap -T fields -e ip.len -Y 'tcp.srcport eq 80' | sort -n >tamanios_HTTP_3_origen.txt
awk -v total=`wc -l <tamanios_HTTP_3_origen.txt` '{ecdf+=1/total;print $1,ecdf}' tamanios_HTTP_3_origen.txt > t_n_HTTPS_3_o_ecdf.txt

#tamanios nivel 3 de paquetes DNS destino
echo "Calculando tamanios nivel 3 de paquetes DNS destino"
tshark -r traza.pcap -T fields -e ip.len -Y 'udp.dstport eq 53' | sort -n >tamanios_DNS_3_destino.txt
awk -v total=`wc -l <tamanios_DNS_3_destino.txt` '{ecdf+=1/total;print $1,ecdf}' tamanios_DNS_3_destino.txt > t_n_DNS_3_d_ecdf.txt

#tamanios nivel 3 de paquetes DNS origen
echo "Calculando tamanios nivel 3 de paquetes DNS origen"
tshark -r traza.pcap -T fields -e ip.len -Y 'udp.srcport eq 53' | sort -n >tamanios_DNS_3_origen.txt
awk -v total=`wc -l <tamanios_DNS_3_origen.txt` '{ecdf+=1/total;print $1,ecdf}' tamanios_DNS_3_origen.txt > t_n_DNS_3_o_ecdf.txt

