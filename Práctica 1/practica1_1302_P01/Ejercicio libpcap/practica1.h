/***************************************************************************
 EjemploPcapNext.c
 Muestra el tiempo de llegada de los primeros 500 paquetes a la interface eth0
y los vuelca a traza nueva con tiempo actual

 Compila: gcc -Wall -o practica1 practica1.c -lpcap
 Autor: Marta Garcín Marín y Lucía Colmenarejo Pérez
 2017 EPS-UAM
***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#define OK 0
#define ERROR 1

#define ETH_FRAME_MAX 1514	// Tamanio maximo trama ethernet

/**
*Esta función captura Ctrl-C al introducirlo por teclado para que finalica la ejecución
*
*Parámetro: de entrada le pasamos la señal que capta del teclado.
*
*Salida: finalización del programa
*/
void handle(int nsignal);

/**
*Esta función inprime los bytes de cada paquete en hexadecimal, tal y como pide en el enunciado
*
*Parámetros: el paquete del que se van a imprimir los bytes en hexadeimal, el número de bytes que se quieren leer y la longtud.
*
*Salida: los bytes en hexadecimal por pantalla(terminal)
*/


void imprimir_paquete(uint8_t *paquete, int N, int len);
