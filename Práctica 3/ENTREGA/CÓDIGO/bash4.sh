#!/bin/bash

echo 
echo

#Tiempos entre llegadas del flujo TCP destino indicado por el generador de la traza
echo "Calculando tiempos entre llegadas del flujo TCP destino"
tshark -r traza.pcap -T fields -e frame.time_delta_displayed -Y 'ip.dst eq 98.64.49.36'  | sort -n > tiempos_llegada_flujo_TCP_destino.txt
awk -v total=`wc -l <tiempos_llegada_flujo_TCP_destino.txt` '{ecdf+=1/total;print $1,ecdf}' tiempos_llegada_flujo_TCP_destino.txt > tiempos_llegada_flujo_TCP_destino_ecdf.txt

#Tiempos entre llegadas del flujo TCP origen indicado por el generador de la traza
echo "Calculando tiempos entre llegadas del flujo TCP origen"
tshark -r traza.pcap -T fields -e frame.time_delta_displayed -Y 'ip.src eq 98.64.49.36' | sort -n > tiempos_llegada_flujo_TCP_origen.txt
awk -v total=`wc -l <tiempos_llegada_flujo_TCP_origen.txt` '{ecdf+=1/total;print $1,ecdf}' tiempos_llegada_flujo_TCP_origen.txt > tiempos_llegada_flujo_TCP_origen_ecdf.txt

#Tiempos entre llegadas del flujo UDP destino indicado por el generador de la traza
echo "Calculando los tiempos entre llegadas del flujo UDP destino"
tshark -r traza.pcap -T fields -e frame.time_delta_displayed -Y 'udp.dstport eq 25256'  | sort -n > tiempos_llegada_flujo_UDP_destino.txt
awk -v total=`wc -l <tiempos_llegada_flujo_UDP_destino.txt` '{ecdf+=1/total;print $1,ecdf}' tiempos_llegada_flujo_UDP_destino.txt > tiempos_llegada_flujo_UDP_destino_ecdf.txt

#Tiempos entre llegadas del flujo UDP origen indicado por el generador de la traza
echo "Calculando los tiempos entre llegadas del flujo UDP origen"
tshark -r traza.pcap -T fields -e frame.time_delta_displayed -Y 'udp.srcport eq 25256'  | sort -n > tiempos_llegada_flujo_UDP_origen.txt
awk -v total=`wc -l <tiempos_llegada_flujo_UDP_origen.txt` '{ecdf+=1/total;print $1,ecdf}' tiempos_llegada_flujo_UDP_origen.txt > tiempos_llegada_flujo_UDP_origen_ecdf.txt

#Cuadal de ancho banda a nivel 2 en bits por segundo de destino
echo "Calculando ancho banda a nivel 2 en bits por segundo de destino"
tshark -r traza.pcap -T fields -e frame.len -e frame.time_relative -Y 'eth.dst eq 00:11:88:CC:33:E1' |
awk '{print int($2), $1}'|
awk '{tiempo[$1] += $2*8;}
				END{
					for(tmp in tiempo)
						print tmp, tiempo[tmp];
				}'|
	sort -nk1 > ancho_banda_destino.txt

#Cuadal de ancho banda a nivel 2 en bits por segundo de origen
echo "Calculando ancho banda a nivel 2 en bits por segundo de origen"
tshark -r traza.pcap -T fields -e frame.len -e frame.time_relative -Y 'eth.src eq 00:11:88:CC:33:E1' |
awk '{print int($2), $1}'|
awk '{tiempo[$1] += $2*8;}
				END{
					for(tmp in tiempo)
						print tmp, tiempo[tmp];
				}'|
	sort -nk1 > ancho_banda_origen.txt