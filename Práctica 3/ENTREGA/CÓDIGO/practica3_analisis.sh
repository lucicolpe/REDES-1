#!/bin/bash

#Ejercicio 1: Porcentaje de paquetes IP  y no IP
echo "EJECUNTADO bash1"
./bash1.sh

echo 
echo

#Ejercicio 2: Top 10 direcciones IP y puertos
echo "EJECUNTADO bash2"
./bash2.sh

echo
echo

#Ejercicio 3, 4 y 5
#Ejercicio 3: ECDF tamaños a nivel 2.
#Ejercicio 4: ECDF tamaños a nivel 3 HTTP.
#Ejercicio 5: ECDF tamaños a nivel 3 DNS.
#creacion de ficheros
echo "EJECUNTADO bash3"
./bash3.sh

echo
echo

#Ejercicio 6, 7 y 8
#Ejercicio 6: ECDF de los tiempos entre llegadas del flujo TCP.
#Ejercicio 7: ECDF de los tiempos entre llegadas del flujo UDP.
#Ejercicio 8: Cuadal de ancho banda a nivel 2 en bits por segundo de destino.
#creacion de ficheros
echo "EJECUNTADO bash4"
./bash4.sh

echo
echo

#graficas gnuplot
echo "EJECUNTADO bash_gnuplot"
./bash_gnuplot.sh

echo 
echo

echo "Borramos ficheros temporales"

#borrado de ficheros inecesarios
rm eth_type.txt protocol.txt
rm direcciones_IP_destino.txt direcciones_IP_origen.txt puertos_TCP_destino.txt puertos_TCP_origen.txt puertos_UDP_destino.txt puertos_UDP_origen.txt
rm tamanios_nivel_2_destino.txt t_n_2_d_ecdf.txt tamanios_nivel_2_origen.txt t_n_2_o_ecdf.txt 
rm tamanios_HTTP_3_destino.txt t_n_HTTPS_3_d_ecdf.txt tamanios_HTTP_3_origen.txt t_n_HTTPS_3_o_ecdf.txt
rm tamanios_DNS_3_destino.txt t_n_DNS_3_d_ecdf.txt tamanios_DNS_3_origen.txt t_n_DNS_3_o_ecdf.txt
rm tiempos_llegada_flujo_TCP_destino.txt tiempos_llegada_flujo_TCP_origen.txt tiempos_llegada_flujo_UDP_destino.txt tiempos_llegada_flujo_UDP_origen.txt
rm tiempos_llegada_flujo_TCP_destino_ecdf.txt tiempos_llegada_flujo_TCP_origen_ecdf.txt tiempos_llegada_flujo_UDP_destino_ecdf.txt tiempos_llegada_flujo_UDP_origen_ecdf.txt
rm ancho_banda_origen.txt ancho_banda_destino.txt

echo "Análisis del tráfico realizado correctamente"