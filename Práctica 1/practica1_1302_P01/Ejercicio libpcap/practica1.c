/***************************************************************************
 *EjemploPcapNext.c
 *Muestra el tiempo de llegada de los primeros 500 paquetes a la interface eth0
 *y los vuelca a traza nueva con tiempo actual

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
#include "practica1.h"

pcap_t *descr=NULL,*descr2=NULL;
pcap_dumper_t *pdumper=NULL;

int contador=0;

/**
*Función que captura la señal de Control C y posteriormente imprime los paquetes de la interfaz.
*También cerramos los descriptores de archivos.
*
*Parámetros: la señak captada, que será Control C.
*/
void handle(int nsignal){
	printf("Control C pulsado\n");
	printf("Paquetes recibidos por la interfaz eth0: %d\n", contador);
	if(descr)
		pcap_close(descr);
	if(descr2)
		pcap_close(descr2);
	if(pdumper)
		pcap_dump_close(pdumper);
	exit(OK);
 }

/**
*Esta función imprime los paquetes en hexadecimal separados cada dos.
*
*Parámetros: el paquete que se quiere imprimir
	     el número de bytes que se quieren imprimir de dicho paquete
	     la longitud del paquete.s
*/
void imprimir_paquete(uint8_t *paquete, int N, int len){
	int i;
	if(N>len){
		printf("Paquete demasiado  corto, imprimiendo paquete:\n");
		for(i=0; i<len; i++){
			printf("%02x ",paquete[i]);
		}
	}else{
		for(i=0;i<N;i++){
			printf("%02x ",paquete[i]);
		}	
	}
	printf("\n\n");
}

int main(int argc, char **argv)
{
	int retorno=0, N;
	char errbuf[PCAP_ERRBUF_SIZE];
	uint8_t *paquete=NULL;
	struct pcap_pkthdr *cabecera=NULL;
	char file_name[256];
	struct timeval time;

	/*Si el número de paquetes es menor que 2 o mayor que 3*/	

	if(argc<2||argc>3){
		printf("Error:Introduce los argumentos correctos: \n  Primer argumento: n primeros bytes de cada paquete capturado\n  Segundo argumento: traza a analizar\n");
		exit(ERROR);
	}

	N = atoi(argv[1]);
		
	if(signal(SIGINT,handle)==SIG_ERR){
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		exit(ERROR);
	}	
		//Apertura de interface
   	if ((descr = pcap_open_live("eth0",2048,0,100, errbuf)) == NULL){ //--> para abrir iterfaz para capturar
		printf("Error: pcap_open_live(): %s, %s %d.\n",errbuf,__FILE__,__LINE__);
		exit(ERROR);
	}
	
	if(argc==2){
		//Volcado de traza
		descr2=pcap_open_dead(DLT_EN10MB,ETH_FRAME_MAX); //--> crea un archivo para ir guardando paquetes
		if (!descr2){
			printf("Error al abrir el dump.\n");
			pcap_close(descr);
			exit(ERROR);
		}
		gettimeofday(&time,NULL);
		sprintf(file_name,"eth0.%lld.pcap",(long long)time.tv_sec); //Tiempo unix en segundos
		pdumper=pcap_dump_open(descr2,file_name);
		if(!pdumper){
			printf("Error al abrir el dumper: %s, %s %d.\n",pcap_geterr(descr2),__FILE__,__LINE__);
			pcap_close(descr);
			pcap_close(descr2);
		}

		while (1){
			retorno = pcap_next_ex(descr,&cabecera,(const u_char **)&paquete);
			if(retorno == -1){ 		//En caso de error
				printf("Error al capturar un paquete %s, %s %d.\n",pcap_geterr(descr),__FILE__,__LINE__);
				pcap_close(descr);
				pcap_close(descr2);
				pcap_dump_close(pdumper);
				exit(ERROR);
			}
			else if(retorno == 0){
				continue;
			}
			else if(retorno==-2){
				break;
			}
			//En otro caso
			contador++;
			cabecera->ts.tv_sec+=172800; //Sumamos dos dias más a la fecha
			printf("Nuevo paquete capturado a las %s",ctime((const time_t*)&(cabecera->ts.tv_sec)));
			imprimir_paquete(paquete,N,cabecera->len);
			if(pdumper){

				pcap_dump((uint8_t *)pdumper,cabecera,paquete);
			}
		}

		pcap_close(descr2);
		pcap_dump_close(pdumper);

	}else{
		descr= pcap_open_offline(argv[2],errbuf);
		if (!descr){
			printf("Error en el pcap_open_offline.\n");
			pcap_close(descr);
			exit(ERROR);
		}
		while (1){
			retorno = pcap_next_ex(descr,&cabecera,(const u_char **)&paquete);
			if(retorno == -1){ 		//En caso de error
				printf("Error al capturar un paquete %s, %s %d.\n",pcap_geterr(descr),__FILE__,__LINE__);
				pcap_close(descr);
				pcap_close(descr2);
				pcap_dump_close(pdumper);
				exit(ERROR);
			}
			else if(retorno == 0){
				continue;
			}
			else if(retorno==-2){
				break;
			}
			//En otro caso
			contador++;
			printf("Nuevo paquete capturado a las %s\n",ctime((const time_t*)&(cabecera->ts.tv_sec)));
			imprimir_paquete(paquete,N,cabecera->len);
			if(pdumper){
				pcap_dump((uint8_t *)pdumper,cabecera,paquete);
			}
		}

	}
	pcap_close(descr);
	return OK;
}
