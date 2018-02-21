/***************************************************************************
 practica4.c
 Inicio, funciones auxiliares y modulos de transmision implmentados y a implementar de la practica 4.
Compila con warning pues falta usar variables y modificar funciones
 
 Compila: make
 Autor: Jose Luis Garcia Dorado
 2014 EPS-UAM v2
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "interface.h"
#include "practica4.h"

/***************************Variables globales utiles*************************************************/
pcap_t* descr, *descr2; //Descriptores de la interface de red
pcap_dumper_t * pdumper;//y salida a pcap
uint64_t cont=0;	//Contador numero de mensajes enviados
char interface[10];	//Interface donde transmitir por ejemplo "eth0"
uint16_t ID=1;		//Identificador IP


void handleSignal(int nsignal){
	printf("Control C pulsado (%"PRIu64")\n", cont);
	pcap_close(descr);
	exit(OK);
}

int main(int argc, char **argv){	

	char errbuf[PCAP_ERRBUF_SIZE];
	char fichero_pcap_destino[CADENAS];
	uint8_t IP_destino_red[IP_ALEN];
	uint16_t MTU;
	uint16_t datalink;
	uint16_t puerto_destino;
	char data[IP_DATAGRAM_MAX];
	uint16_t pila_protocolos[CADENAS];


	int long_index=0;
	char opt;
	char flag_iface = 0, flag_ip = 0, flag_port = 0, flag_file = 0;

	static struct option options[] = {
		{"if",required_argument,0,'1'},
		{"ip",required_argument,0,'2'},
		{"pd",required_argument,0,'3'},
		{"f",required_argument,0,'4'},
		{"h",no_argument,0,'5'},
		{0,0,0,0}
	};

		//Dos opciones: leer de stdin o de fichero, adicionalmente para pruebas si no se introduce argumento se considera que el mensaje es "Payload "
	while ((opt = getopt_long_only(argc, argv,"1:2:3:4:5", options, &long_index )) != -1) {
		switch (opt) {

			case '1' :

				flag_iface = 1;
					//Por comodidad definimos interface como una variable global
				sprintf(interface,"%s",optarg);
				break;

			case '2' : 

				flag_ip = 1;
					//Leemos la IP a donde transmitir y la almacenamos en orden de red
				if (sscanf(optarg,"%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"",
				                   &(IP_destino_red[0]),&(IP_destino_red[1]),&(IP_destino_red[2]),&(IP_destino_red[3])) != IP_ALEN){
					printf("Error: Fallo en la lectura IP destino %s\n", optarg);
					exit(ERROR);
				}

				break;

			case '3' :

				flag_port = 1;
					//Leemos el puerto a donde transmitir y la almacenamos en orden de hardware
				puerto_destino=atoi(optarg);
				break;

			case '4' :

				if(strcmp(optarg,"stdin")==0) {
					if (fgets(data, sizeof data, stdin)==NULL) {
						  	printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
						return ERROR;
					}
					sprintf(fichero_pcap_destino,"%s%s","stdin",".pcap");
				} else {
					FILE * pf;
					pf = fopen(optarg, "r");
					if(pf==NULL){
						printf("Error al abrir el fichero de lectura %s: %s %s %d.\n", optarg,errbuf,__FILE__,__LINE__);
						return ERROR;
					}
					if (fgets(data, sizeof data, pf)==NULL) {
						printf("Error leyendo desde %s: %s %s %d.\n",optarg, errbuf,__FILE__,__LINE__);
						fclose(pf);
						return ERROR;
					}
					sprintf(fichero_pcap_destino,"%s%s",optarg,".pcap");
					
				}
				flag_file = 1;

				break;

			case '5' : printf("Ayuda. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc); exit(ERROR);
				break;

			case '?' : printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc); exit(ERROR);
				break;

			default: printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc); exit(ERROR);
				break;
        }
    }

	if ((flag_iface == 0) || (flag_ip == 0) || (flag_port == 0)){
		printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc);
		exit(ERROR);
	} else {
		printf("Interface:\n\t%s\n",interface);
		printf("IP:\n\t%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\n",IP_destino_red[0],IP_destino_red[1],IP_destino_red[2],IP_destino_red[3]);
		printf("Puerto destino:\n\t%"PRIu16"\n",puerto_destino);
	}

	if (flag_file == 0) {
		sprintf(data,"%s","Payload "); //Deben ser pares!
		sprintf(fichero_pcap_destino,"%s%s","debugging",".pcap");
	}

	if(signal(SIGINT,handleSignal)==SIG_ERR){
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		return ERROR;
	}
		//Inicializamos las tablas de protocolos
	if(inicializarPilaEnviar()==ERROR){
      	printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
		//Leemos el tamano maximo de transmision del nivel de enlace
	if(obtenerMTUInterface(interface, &MTU)==ERROR)
		return ERROR;
		//Descriptor de la interface de red donde inyectar trafico
	if ((descr = pcap_open_live(interface,MTU+ETH_HLEN,0, 0, errbuf)) == NULL){
		printf("Error: pcap_open_live(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}

	datalink=(uint16_t)pcap_datalink(descr); //DLT_EN10MB==Ethernet

		//Descriptor del fichero de salida pcap para debugging
	descr2=pcap_open_dead(datalink,MTU+ETH_HLEN);
	pdumper=pcap_dump_open(descr2,fichero_pcap_destino);

		//Formamos y enviamos el trafico, debe enviarse un unico segmento por llamada a enviar() aunque luego se traduzca en mas de un datagrama
		//Primero un paquete UDP
		//Definimos la pila de protocolos que queremos seguir
	pila_protocolos[0]=UDP_PROTO; pila_protocolos[1]=IP_PROTO; pila_protocolos[2]=ETH_PROTO;
		//Rellenamos los parametros necesario para enviar el paquete a su destinatario y proceso
	Parametros parametros_udp; memcpy(parametros_udp.IP_destino,IP_destino_red,IP_ALEN); parametros_udp.puerto_destino=puerto_destino;
		//Enviamos
	if(enviar((uint8_t*)data,strlen(data),pila_protocolos,&parametros_udp)==ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else	cont++;

	printf("Enviado mensaje %"PRIu64", almacenado en %s\n\n\n", cont,fichero_pcap_destino);

		//Luego, un paquete ICMP en concreto un ping
	pila_protocolos[0]=ICMP_PROTO; pila_protocolos[1]=IP_PROTO; pila_protocolos[2]=0;
	Parametros parametros_icmp; parametros_icmp.tipo=PING_TIPO; parametros_icmp.codigo=PING_CODE; memcpy(parametros_icmp.IP_destino,IP_destino_red,IP_ALEN);
	if(enviar((uint8_t*)"Probando a hacer un ping",strlen("Probando a hacer un ping"),pila_protocolos,&parametros_icmp)==ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else	cont++;
	printf("Enviado mensaje %"PRIu64", ICMP almacenado en %s\n\n", cont,fichero_pcap_destino);

		//Cerramos descriptores
	pcap_close(descr);
	pcap_dump_close(pdumper);
	pcap_close(descr2);
	return OK;
}


/****************************************************************************************
* Nombre: enviar 									*
* Descripcion: Esta funcion envia un mensaje						*
* Argumentos: 										*
*  -mensaje: mensaje a enviar								*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen mensaje						*
*  -parametros: parametros necesario para el envio (struct parametros)			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t enviar(uint8_t* mensaje, uint64_t longitud,uint16_t* pila_protocolos,void *parametros){
	uint16_t protocolo=pila_protocolos[0];
	printf("Enviar(%"PRIu16") %s %d.\n",protocolo,__FILE__,__LINE__);
	if(protocolos_registrados[protocolo]==NULL){
		printf("Protocolo %"PRIu16" desconocido\n",protocolo);
		return ERROR;
	}
	else {
		return protocolos_registrados[protocolo](mensaje,longitud,pila_protocolos,parametros);
	}
	return ERROR;
}


/***************************TODO Pila de protocolos a implementar************************************/

/****************************************************************************************
* Nombre: moduloUDP 									*
* Descripcion: Esta funcion implementa el modulo de envio UDP				*
* Argumentos: 										*
*  -mensaje: mensaje a enviar								*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen mensaje						*
*  -parametros: parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloUDP(uint8_t* mensaje,uint64_t longitud, uint16_t* pila_protocolos,void *parametros){
	uint8_t segmento[UDP_SEG_MAX]={0};
	uint16_t puerto_origen = 0;
	uint16_t aux16;
	uint32_t pos=0;
	uint16_t protocolo_inferior=pila_protocolos[1];
	printf("modulo UDP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);

	if (longitud>(UDP_SEG_MAX-UDP_HLEN)){ //pow(2,16)-UDP_HLEN-IP_HLEN-1
		printf("Error: mensaje demasiado grande para UDP (%f).\n",(pow(2,16)-UDP_HLEN));
		return ERROR;
	}

	Parametros * udpdatos = (Parametros*)parametros;

	//Puerto origen
	obtenerPuertoOrigen(&puerto_origen); 
	aux16=htons(puerto_origen);
	memcpy(segmento+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);
	
	//Puerto destino
	uint16_t puerto_destino=udpdatos->puerto_destino;
	aux16=htons(puerto_destino);
	memcpy(segmento+pos, &aux16, sizeof(uint16_t));
	pos+=sizeof(uint16_t);
	
	//Longitud
	aux16=htons(longitud+UDP_HLEN);
	memcpy(segmento+pos, &aux16, sizeof(uint16_t));
	pos+=sizeof(uint16_t);
	
	//Checksum (no hace falta, se queda como está)
	aux16=0;
	memcpy(segmento+pos, &aux16, sizeof(uint16_t));
	pos+=sizeof(uint16_t);
	
	//Mensaje
	memcpy(segmento+pos, mensaje, longitud*sizeof(uint8_t));
	pos+=longitud*sizeof(uint8_t);

	//Se llama al protocolo definido de nivel inferior a traves de los punteros registrados en la tabla de protocolos registrados
	return protocolos_registrados[protocolo_inferior](segmento,longitud+pos,pila_protocolos,parametros);
}


/****************************************************************************************
* Nombre: moduloIP 									*
* Descripcion: Esta funcion implementa el modulo de envio IP				*
* Argumentos: 										*
*  -segmento: segmento a enviar								*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen el segmento						*
*  -parametros: parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloIP(uint8_t* segmento, uint64_t longitud, uint16_t* pila_protocolos,void *parametros){
	uint8_t datagrama[IP_DATAGRAM_MAX]={0};
	uint32_t aux32;
	uint16_t aux16, mtu;
	uint8_t aux8;
	uint32_t pos=0;
	uint8_t IP_origen[IP_ALEN],IP_gateway[IP_ALEN];
	uint8_t* IP_aux= NULL; // IP_aux[IP_ALEN] no valido al asignarle la IP_destino
	uint16_t protocolo_superior=pila_protocolos[0];
	uint16_t protocolo_inferior=pila_protocolos[2];
	uint8_t mascara[IP_ALEN],IP_rango_origen[IP_ALEN],IP_rango_destino[IP_ALEN];
	int n_packets;
	int i;
	pila_protocolos++;
	printf("modulo IP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);

	if (longitud> IP_DATAGRAM_MAX - 20 ){ 
		printf("Error: longuitud demasiado grande para IP.\n");
		return ERROR;
	}
	
	
	
	Parametros * ipdatos=(Parametros*)parametros;
	uint8_t* IP_destino=ipdatos->IP_destino;
	uint8_t version =IP_ALEN;
	
	// version: 4 con cabecera: 5
	aux8=version;
	aux8<<=4;
	aux8+=5;
	memcpy(datagrama+pos, &aux8, sizeof(uint8_t));
	pos+=sizeof(uint8_t);
	
	//Tipo de servicio
	aux8=0;
	memcpy(datagrama+pos, &aux8, sizeof(uint8_t));
	pos+=sizeof(uint8_t);
	
	//longitud total
	aux16 = longitud + 5*4;//?? * sizeof(uint8_t)
	aux16 = htons(aux16);
	memcpy(datagrama+pos, &aux16, sizeof(uint16_t));
	pos+=sizeof(uint16_t);
	
	//identificador ( num aleatorio)
	aux16 = (uint16_t)ID;
	memcpy(datagrama+pos, &aux16, sizeof(uint16_t));
	pos+=sizeof(uint16_t);
	
	//flags + offset
	aux16=0; //flags
	aux16<<=13;
	aux16+=0; //offset
	memcpy(datagrama+pos, &aux16, sizeof(uint16_t));
	pos+=sizeof(uint16_t);
	
	//TTL 
	aux8=64;
	memcpy(datagrama+pos, &aux8, sizeof(uint8_t));
	pos+=sizeof(uint8_t);
	
	//Protocolo
	printf("protocolo: %"PRIu16"", protocolo_superior); 
	aux8= (uint8_t )protocolo_superior;
	memcpy(datagrama+pos, &aux8, sizeof(uint8_t));
	pos+=sizeof(uint8_t);
	
	//checksum al final
	aux16=0;
	memcpy(datagrama+pos, &aux16, sizeof(uint16_t));
	pos+=sizeof(uint16_t);
	
	//IPorigen	
	//obtener ip origen 
	obtenerIPInterface(interface, IP_origen);
	aux32= * ((uint32_t * ) IP_origen);
	memcpy(datagrama+pos, &aux32, sizeof(uint32_t));
	pos+=sizeof(uint32_t);

	//IPdestino
	aux32= *((uint32_t * ) IP_destino);
	memcpy(datagrama+pos, &aux32, sizeof(uint32_t));
	pos+=sizeof(uint32_t);

	
	//obtener mascara para coger la direccion ethernet de la interfaz
	obtenerMascaraInterface(interface, mascara);
	
	//Comprobamos si el destino esta en nuestra subred
	if(aplicarMascara(IP_origen , mascara, (uint32_t) version, IP_rango_origen)==ERROR){
		printf("Error al aplicar la mascara\n");
		return ERROR;
	}
	if(aplicarMascara(IP_destino , mascara, (uint32_t) version, IP_rango_destino)==ERROR){
		printf("Error al aplicar la mascara\n");
		return ERROR;
	}
	if( *( (uint32_t *)IP_rango_origen) == *( (uint32_t *)IP_rango_destino)){
	//misma subred, entonces mandamos a mac del destino
		IP_aux=IP_destino;

	}else{
	//diferente subred entonces mandamos al router
		
		if(obtenerGateway(interface, IP_gateway)== ERROR){
			printf("Error en ObtenerGateway");
			return ERROR;
		}
		IP_aux = IP_gateway;
	}

	ARPrequest(interface,IP_aux,ipdatos->ETH_destino);
	
	//Fragmentacion
	obtenerMTUInterface(interface, &mtu);
	n_packets=1 + (long int) longitud / ((int ) mtu - 20 );
	
	//Llamada a niveles inferiores
	for (i=0;i<n_packets-1;i++){
		
		//total length
		aux16=mtu;
		aux16=htons(aux16);
		memcpy(datagrama+sizeof(uint16_t), &aux16, sizeof(uint16_t));
		
		//flags +offset
		aux16=1;
		aux16<<=13;
		aux16+=i*(mtu-20)/8;
		aux16=htons(aux16);
		memcpy(datagrama+3*sizeof(uint16_t), &aux16, sizeof(uint16_t));
		
		//calculo de checksum
		aux16=0;
		memcpy(datagrama+5*sizeof(uint16_t), &aux16, sizeof(uint16_t)); //ponemos checksum a 0 antes de calcularlo
		if(calcularChecksum(pos, datagrama, (uint8_t *) (&aux16))==ERROR){
			printf("Error al calcular Checksum de IP\n");
			return ERROR;
		}
		memcpy(datagrama+5*sizeof(uint16_t), &aux16, sizeof(uint16_t));
		
		//mensaje (segmento)
		memcpy(datagrama+pos, segmento, mtu-20);
		segmento+=(mtu-20);
		protocolos_registrados[protocolo_inferior]( datagrama,mtu,pila_protocolos,parametros);
	}
	
	//Ultimo fragmento
	longitud = (uint64_t)((long int) longitud % ((int ) (mtu - 20))) ;
	
	//total length
	aux16=longitud + 20;
	aux16=htons(aux16);
	memcpy(datagrama+sizeof(uint16_t), &aux16, sizeof(uint16_t));
	
	//flags+offset
	aux16=0;
	aux16<<=13;
	aux16+=i*(mtu-20)/8;
	aux16=htons(aux16);
	memcpy(datagrama+3*sizeof(uint16_t), &aux16, sizeof(uint16_t));
	
	//calculo de checksum
	aux16=0;
	memcpy(datagrama+5*sizeof(uint16_t), &aux16, sizeof(uint16_t)); //ponemos checksum a 0 antes de calcularlo
	if(calcularChecksum(pos, datagrama, (uint8_t *) (&aux16))==ERROR){
		printf("Error al calcular Checksum de IP\n");
		return ERROR;
	}
	memcpy(datagrama+5*sizeof(uint16_t), &aux16, sizeof(uint16_t));
	//mensaje (segmento)
	
	memcpy(datagrama+pos, segmento, longitud);

	return protocolos_registrados[protocolo_inferior](datagrama,longitud+pos,pila_protocolos,parametros);



}


/****************************************************************************************
* Nombre: moduloETH 									*
* Descripcion: Esta funcion implementa el modulo de envio Ethernet			*
* Argumentos: 										*
*  -datagrama: datagrama a enviar							*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen el datagrama						*
*  -parametros: Parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloETH(uint8_t* datagrama, uint64_t longitud, uint16_t* pila_protocolos,void *parametros){

	uint16_t aux16;
	uint32_t pos=0;
	uint8_t MAC_origen[ETH_ALEN] ;
	uint8_t trama[ETH_FRAME_MAX]={0};

	pila_protocolos++;

	printf("modulo ETH(fisica) %s %d.\n",__FILE__,__LINE__);	

	if (longitud> ETH_FRAME_MAX - ETH_HLEN){
		printf("Error: longuitud demasiado grande para ETH.\n");
		return ERROR;
	}

	Parametros * ethdatos=(Parametros*)parametros;

	//Direccion destino
	uint8_t* MAC_destino = ethdatos->ETH_destino;
	memcpy(trama+pos, MAC_destino, sizeof(uint8_t)*ETH_ALEN);
	pos+=sizeof(uint8_t) * ETH_ALEN;
	
	//Direccion origen
	obtenerMACdeInterface(interface, MAC_origen);
	memcpy(trama+pos, MAC_origen, sizeof(uint8_t)*ETH_ALEN);
	pos+=sizeof(uint8_t) * ETH_ALEN;
	
	//Tipo de ethernet
	aux16= htons((uint16_t)IP_PROTO);
	memcpy(trama+pos, &aux16, sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	//mensaje (datagrama)
	memcpy(trama+pos, datagrama, longitud);
	
	//Enviar a capa fisica
	int size = (int)longitud+pos; 
	printf("Longitud del paquete a transmitir: %d\n", size);
	if(pcap_sendpacket(descr, trama, longitud+pos)==-1){
		printf("Error inyectando el paquete %s %d.\n",__FILE__,__LINE__);
		return ERROR;
	}
	//Almacenamos la salida por cuestiones de debugging
	struct pcap_pkthdr header;
	struct pcap_pkthdr * h = &header;
	gettimeofday(&(h->ts), NULL);
	h->len = size;
	h->caplen = size;
	
	pcap_dump((u_char *) pdumper, h, trama);

	return OK;
}


/****************************************************************************************
* Nombre: moduloICMP 									*
* Descripcion: Esta funcion implementa el modulo de envio ICMP				*
* Argumentos: 										*
*  -mensaje: mensaje a anadir a la cabecera ICMP					*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen el mensaje						*
*  -parametros: parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloICMP(uint8_t* mensaje,uint64_t longitud, uint16_t* pila_protocolos,void *parametros){

	uint8_t datagrama[ICMP_DATAGRAM_MAX]={0};
	uint16_t aux16;
	uint8_t aux8;
	uint32_t pos=0;
	uint16_t protocolo_inferior=pila_protocolos[1];


	printf("modulo ICMP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);

	if (longitud>ICMP_DATAGRAM_MAX-ICMP_HLEN){
		printf("Error: mensaje demasiado grande para ICMP (%d).\n",ICMP_DATAGRAM_MAX);
		return ERROR;
	}

	Parametros * icmpdatos=(Parametros*)parametros;
	
	//Tipo
	aux8 = icmpdatos->tipo;
	memcpy(datagrama+pos, &aux8, sizeof(uint8_t));
	pos+=sizeof(uint8_t);

	//Codigo
	aux8 = icmpdatos->codigo;
	memcpy(datagrama+pos, &aux8, sizeof(uint8_t));
	pos+=sizeof(uint8_t);

	//Checksum
	aux16 = 0;
	memcpy(datagrama+pos, &aux16, sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	//Identificador
	aux16 = htons(ID);
	memcpy(datagrama+pos, &aux16, sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	//Numero de secuencia
	time_t t;
	srand((unsigned) time(&t));
	aux16 = (uint16_t)rand();
	memcpy(datagrama+pos, &aux16, sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	//Mensaje
	memcpy(datagrama+pos, mensaje, longitud);

	//Calcular Checksum
	if(calcularChecksum(longitud+pos, datagrama, (uint8_t *) (&aux16))==ERROR){
		printf("Error al calcular Checksum de ICMP\n");
		return ERROR;
	}

	memcpy(datagrama+sizeof(uint16_t), &aux16, sizeof(uint16_t));

	return protocolos_registrados[protocolo_inferior](datagrama,longitud+pos,pila_protocolos,icmpdatos);

}


/***************************Funciones auxiliares a implementar***********************************/

/****************************************************************************************
* Nombre: aplicarMascara 								*
* Descripcion: Esta funcion aplica una mascara a una vector				*
* Argumentos: 										*
*  -IP: IP a la que aplicar la mascara en orden de red					*
*  -mascara: mascara a aplicar en orden de red						*
*  -longitud: bytes que componen la direccion (IPv4 == 4)				*
*  -resultado: Resultados de aplicar mascara en IP en orden red				*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t aplicarMascara(uint8_t* IP, uint8_t* mascara, uint32_t longitud, uint8_t* resultado){
	int i=0;
	if (!IP || ! mascara || ! resultado){
		printf("Error: aplicarMacara(): entradas nulas.\n");
		return ERROR;
	}
	for(i=0;i<longitud;i++){
		resultado[i]= IP[i] & mascara[i];
	}
	return OK;

}


/***************************Funciones auxiliares implementadas**************************************/

/****************************************************************************************
* Nombre: mostrarPaquete 								*
* Descripcion: Esta funcion imprime por pantalla en hexadecimal un vector		*
* Argumentos: 										*
*  -paquete: bytes que conforman un paquete						*
*  -longitud: Bytes que componen el mensaje						*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t mostrarPaquete(uint8_t * paquete, uint32_t longitud){
	uint32_t i;
	printf("Paquete:\n");
	for (i=0;i<longitud;i++){
		printf("%02"PRIx8" ", paquete[i]);
	}
	printf("\n");
	return OK;
}


/****************************************************************************************
* Nombre: calcularChecksum							     	*
* Descripcion: Esta funcion devuelve el ckecksum tal como lo calcula IP/ICMP		*
* Argumentos:										*
*   -longitud: numero de bytes de los datos sobre los que calcular el checksum		*
*   -datos: datos sobre los que calcular el checksum					*
*   -checksum: checksum de los datos (2 bytes) en orden de red! 			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t calcularChecksum(uint16_t longitud, uint8_t *datos, uint8_t *checksum) {
    uint16_t word16;
    uint32_t sum=0;
    int i;
    // hacer palabras de 16 bits de cada dos palabras adyacentes de 8 bits en el paquete y sumarlas
    for (i=0; i<longitud; i=i+2){
        word16 = (datos[i]<<8) + datos[i+1];
        sum += (uint32_t)word16;       
    }
    // tomar solo 16 bits de la suma de 32 bits y sumar el acarreo
    while (sum>>16) {
        sum = (sum & 0xFFFF)+(sum >> 16);
    }
    // el complemento de uno el resultado
    sum = ~sum;      
    checksum[0] = sum >> 8;
    checksum[1] = sum & 0xFF;
    return OK;
}


/***************************Funciones inicializacion implementadas*********************************/

/****************************************************************************************
* Nombre: inicializarPilaEnviar     							*
* Descripcion: inicializar la pila de red para enviar registrando los distintos modulos *
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t inicializarPilaEnviar() {
	bzero(protocolos_registrados,MAX_PROTOCOL*sizeof(pf_notificacion));
	if(registrarProtocolo(ETH_PROTO, moduloETH, protocolos_registrados)==ERROR)
		return ERROR;
	if(registrarProtocolo(IP_PROTO, moduloIP, protocolos_registrados)==ERROR)
		return ERROR;
	if(registrarProtocolo(UDP_PROTO, moduloUDP, protocolos_registrados)==ERROR)
		return ERROR;
	if(registrarProtocolo(ICMP_PROTO, moduloICMP, protocolos_registrados)==ERROR)
		return ERROR;
	return OK;
}


/****************************************************************************************
* Nombre: registrarProtocolo 								*
* Descripcion: Registra un protocolo en la tabla de protocolos 				*
* Argumentos:										*
*  -protocolo: Referencia del protocolo (ver RFC 1700)					*
*  -handleModule: Funcion a llamar con los datos a enviar				*
*  -protocolos_registrados: vector de funciones registradas 				*
* Retorno: OK/ERROR 									*
*****************************************************************************************/

uint8_t registrarProtocolo(uint16_t protocolo, pf_notificacion handleModule, pf_notificacion* protocolos_registrados){
	if(protocolos_registrados==NULL ||  handleModule==NULL){		
		printf("Error: registrarProtocolo(): entradas nulas.\n");
		return ERROR;
	}
	else
		protocolos_registrados[protocolo]=handleModule;
	return OK;
}


