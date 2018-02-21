/**********************************************************************************
 practica2.h
 Contiene la decalaracion de las funciones y las macros a utilizar en practica2.c 
 Autor: Marta García Marín y Lucía Colmenarejo Pérez
 2017 EPS-UAM
**********************************************************************************/

#ifndef PRACTICA2_H
#define PRACTICA2_H

#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <inttypes.h>

/*Definicion de constantes *************************************************/
#define ETH_ALEN      6      /* Tamanio de la direccion ethernet           */
#define ETH_HLEN      14     /* Tamanio de la cabecera ethernet            */
#define ETH_TLEN      2      /* Tamanio del campo tipo ethernet            */
#define TIPO_IP 	  2048	 /* Corresponde al tipo ip, para detectar IPv4 */
#define TIPO_ARC	2054
/*El campo de CRC, es un código de detección de errores que ocupa 4 bits   */
#define ETH_FRAME_MAX 1514   /* Tamanio maximo la trama ethernet (sin CRC) */
#define ETH_FRAME_MIN 60     /* Tamanio minimo la trama ethernet (sin CRC) */
#define ETH_DATA_MAX  (ETH_FRAME_MAX - ETH_HLEN) /* Tamano maximo y minimo de los datos de una trama ethernet*/
#define ETH_DATA_MIN  (ETH_FRAME_MIN - ETH_HLEN)
#define IP_ALEN 4			/* Tamanio de la direccion IP, supongo que se referirá a 4 bytes= 32 bits*/
#define OK 0
#define ERROR 1
#define PACK_READ 1
#define PACK_ERR -1
#define TRACE_END -2
#define NO_FILTER 0


/**
 * Funcion que analiza los campos de los distintos niveles que tiene un paquete
 * Recibe por parametro:
 * 		hdr: el puntero a la cabecera del paquete  
 * 		pack: el puntero que apunta a los campos dentro del paquete
 **/
void analizar_paquete(const struct pcap_pkthdr *hdr, const uint8_t *pack);

/**
 * Funcion que captura la senial del Control C
 **/
void handleSignal(int nsignal);

#endif
