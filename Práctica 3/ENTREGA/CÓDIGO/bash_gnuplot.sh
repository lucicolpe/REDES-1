#!/bin/bash

echo
echo

#Borrado previo
rm GNUplot_t_n_2_ecdf.txt.png GNUplot_t_n_HTTPS_3_ecdf.txt.png GNUplot_t_n_DNS_3_ecdf.txt.png
rm GNUplot_ancho_banda_destino.txt.png GNUplot_ancho_banda_origen.txt.png GNUplot_tiempos_llegada_flujo_TCP_ecdf.txt.png GNUplot_tiempos_llegada_flujo_UDP_ecdf.txt.png

#Tamanios nivel 2 origen y destinO
echo "Generando gráfica de tamanios de nivel 2 origen y destino"
gnuplot -e "set title 'Tamanios nivel 2 destino';set xlabel 'tamanios';set ylabel 'distribucion';plot 't_n_2_d_ecdf.txt' using 1:2 with steps title 'Destino', 't_n_2_o_ecdf.txt' using 1:2 with steps title 'Origen';set term pngcairo;set output 'GNUplot_t_n_2_ecdf.txt.png';replot;set output"

#Tamanios nivel 3 de paquetes HTTP origen y destino
echo "Generando gráfica de tamanios de nivel 3 de paquetes HTTP origen y destino"
gnuplot -e "set title 'Tamanios nivel 3 de paquetes HTTP destino';set xlabel 'tamanios';set ylabel 'distribucion';plot 't_n_HTTPS_3_d_ecdf.txt' using 1:2 with steps title 'Destino', 't_n_HTTPS_3_o_ecdf.txt' using 1:2 with steps title 'Origen';set term pngcairo;set output 'GNUplot_t_n_HTTPS_3_ecdf.txt.png';replot;set output"

#Tamanios nivel 3 de paquetes DNS origen y destino
echo "Generando gráfica de tamanios de nivel 3 de paquetes DNS origen y destino"
gnuplot -e "set title 'Tamanios nivel 3 de paquetes DNS destino';set xlabel 'tamanios';set ylabel 'distribucion';plot 't_n_DNS_3_d_ecdf.txt' using 1:2 with steps title 'Destino', 't_n_DNS_3_o_ecdf.txt' using 1:2 with steps title 'Origen';set term pngcairo;set output 'GNUplot_t_n_DNS_3_ecdf.txt.png';replot;set output"

#Tiempos de llegada del flujo TCP (origen y destino)
echo "Generando gráfica de tiempos de llegada del flujo TCP"
gnuplot -e "set title 'Tiempos de llegada del flujo TCP';set xlabel 'Tiempos';set logscale x;set ylabel 'distribucion';plot 'tiempos_llegada_flujo_TCP_destino_ecdf.txt' using 1:2 with steps title 'Destino', 'tiempos_llegada_flujo_TCP_origen_ecdf.txt' using 1:2 with steps title 'Origen';set term pngcairo;set output 'GNUplot_tiempos_llegada_flujo_TCP_ecdf.txt.png';replot;set output"

#Tiempos de llegada del flujo UDP(destino)
echo "Generando gráfica de tiempos de llegada del flujo UDP (no tenemos de origen debido a que no hay tráfico en ese sentido)"
gnuplot -e "set title 'Tiempos de llegada del flujo UDP';set xlabel 'Tiempos';set logscale x;set ylabel 'distribucion';plot 'tiempos_llegada_flujo_UDP_destino_ecdf.txt' using 1:2 with steps title 'Destino'; set term pngcairo;set output 'GNUplot_tiempos_llegada_flujo_UDP_ecdf.txt.png';replot;set output"

#Anch0 de banda de destino
echo "Generando gráfica de ancho de banda destino"
gnuplot -e "set title 'Ancho banda destino';set xlabel 'Tiempo';set ylabel 'bits';plot 'ancho_banda_destino.txt' using 1:2 with lines title 'Destino';set term pngcairo;set output 'GNUplot_ancho_banda_destino.txt.png';replot;set output"

#Ancho de banda de origen
echo "Generando gráfica de ancho de banda origen"
gnuplot -e "set title 'Ancho banda origen';set xlabel 'Tiempo';set ylabel 'bits';plot 'ancho_banda_origen.txt' using 1:2 with lines title 'Origen';set term pngcairo;set output 'GNUplot_ancho_banda_origen.txt.png';replot;set output"
