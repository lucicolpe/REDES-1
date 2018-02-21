#!/bin/bash

echo 
echo

rm top_IP_origen_bytes.txt top_IP_destino_bytes.txt top_puertos_destino_TCP.txt top_puertos_origen_TCP.txt top_puertos_origen_UDP_bytes.txt top_puertos_destino_UDP_bytes.txt

#################################################################################
#IP

echo "Calculando top IP destino"
tshark -r traza.pcap -T fields -e ip.dst>direcciones_IP_destino.txt
echo "Calculando top IP origen"
tshark -r traza.pcap -T fields -e ip.src>direcciones_IP_origen.txt
sort "direcciones_IP_destino.txt" | uniq -c |sort -nrk1,1 |head -n 10 >"top_IP_destino.txt"
sort "direcciones_IP_origen.txt" | uniq -c |sort -nrk1,1 |head -n 10 >"top_IP_origen.txt"


echo "Calculando top IP destino en bytes"
tshark -r traza.pcap -T fields  -e ip.src -e frame.len |
awk '{bytessrc[$1] += $2;}
					END{
						for (ip in bytessrc)
							print ip, bytessrc[ip];
					}' |

	sort -nrk2 |
	head -n 10 > top_IP_origen_bytes.txt
echo "Calculando top IP origen en bytes"
tshark -r traza.pcap -T fields  -e ip.dst -e frame.len |
awk '{bytesdst[$1] += $2;}
					END{for (ip in bytesdst)
						print ip, bytesdst[ip];
					}' |

	sort -nrk2 |
	head -n 10 > top_IP_destino_bytes.txt


#################################################################################
#TCP

echo "Calculando top puertos TCP destino"
tshark -r traza.pcap -T fields -e tcp.dstport -Y "tcp">puertos_TCP_destino.txt
echo "Calculando top puertos TCP origen"
tshark -r traza.pcap -T fields -e tcp.srcport -Y "tcp">puertos_TCP_origen.txt
sort "puertos_TCP_destino.txt" | uniq -c |sort -nrk1,1 |head -n 10 >"top_puertos_destino_TCP.txt"
sort "puertos_TCP_origen.txt" | uniq -c |sort -nrk1,1 |head -n 10 >"top_puertos_origen_TCP.txt"

echo "Calculando top puertos TCP destino en bytes"
tshark -r traza.pcap -T fields -e tcp.dstport -e frame.len |
awk '{bytesdst[$1] += $2;}
					END{
						for (ip in bytesdst)
							print ip, bytesdst[ip];
					}' |

	sort -nrk2 |
	head -n 10 > top_puertos_destino_TCP_bytes.txt
echo "Calculando top puertos TCP origen en bytes"
tshark -r traza.pcap -T fields  -e tcp.srcport -e frame.len |
awk '{bytessrc[$1] += $2;}
					END{for (ip in bytessrc)
						print ip, bytessrc[ip];
					}' |

	sort -nrk2 |
	head -n 10 > top_puertos_origen_TCP_bytes.txt


#################################################################################
#UDP

echo "Calculando top puertos UDP destino"
tshark -r traza.pcap -T fields -e udp.dstport -Y "udp">puertos_UDP_destino.txt
echo "Calculando top puertos UDP origen"
tshark -r traza.pcap -T fields -e udp.srcport -Y "udp">puertos_UDP_origen.txt
sort "puertos_UDP_destino.txt" | uniq -c |sort -nrk1,1 |head -n 10 >"top_puertos_destino_UDP.txt"
sort "puertos_UDP_origen.txt" | uniq -c |sort -nrk1,1 |head -n 10 >"top_puertos_origen_UDP.txt"


echo "Calculando top puertos UDP destino en bytes"
tshark -r traza.pcap -T fields  -e udp.dstport -e frame.len |
awk '{bytesdst[$1] += $2;}
					END{
						for (ip in bytesdst)
							print ip, bytesdst[ip];
					}' |

	sort -nrk2 |
	head -n 10 > top_puertos_destino_UDP_bytes.txt
echo "Calculando top puertos UDP origen en bytes"
tshark -r traza.pcap -T fields  -e udp.srcport -e frame.len |
awk '{bytessrc[$1] += $2;}
					END{for (ip in bytessrc)
						print ip, bytessrc[ip];
					}' |

	sort -nrk2 |
	head -n 10 > top_puertos_origen_UDP_bytes.txt