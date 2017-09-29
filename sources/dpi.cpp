// "dpi.cpp"

#include <iostream>
#include <dpi.h>
#include <iomanip>
#include <string>
#include <sstream>
#include <enlace.h>
#include <cstdlib>

using namespace std;

DPI::DPI(const char *interfaz, const char *filtro) {
	interfazCap = (char *)interfaz;
	filtroCap = (char *)filtro;
	if (pcap_lookupnet(interfazCap, &net, &mask, error) == -1) {
		cout << "No se pudo obtener la máscara de red para la interfaz " << interfazCap << endl;
		mask = 0;
	}
}

char* DPI::getInterfazCaptura() {
	return interfazCap;
}

bool DPI::comenzarCaptura() {
	descriptor = pcap_open_live(interfazCap,1500,0,0,error);
	if (descriptor == NULL)
		return false;

	if (pcap_compile(descriptor, &fp, filtroCap, 0, net) == -1) {
		cout << "Expresión inválida. No se puede analizar la expresión de filtro." << endl;
	}

	if (pcap_setfilter(descriptor, &fp) == -1) {
		cout << "No se pudo instalar el filtro." << endl;
	}

	return true;
}

void DPI::parsePaquete(vector<Enlace*> *vecEnl, DBconnector *conector) {
	paquete = pcap_next(descriptor,&cabecera);
//	const sniff_ethernet *cabecera_ethernet; // The ethernet header
	const sniff_ip *cabecera_ip; // The IP header
	const sniff_tcp *cabecera_tcp; // The TCP header
	const sniff_ssl_H *ssl_payload_H; // SSL 1st Header
	const sniff_ssl_L *ssl_payload_L; // SSL 2nd Header
	u_char *payload; // Packet payload
	u_int size_cabecera_ip;
	u_int size_cabecera_tcp;
	u_int size_payload;

//	cabecera_ethernet = (sniff_ethernet*)(paquete);
	cabecera_ip = (sniff_ip*)(paquete + SIZE_ETHERNET);
	size_cabecera_ip = IP_HL(cabecera_ip)*4;
	cabecera_tcp = (sniff_tcp*)(paquete + SIZE_ETHERNET + size_cabecera_ip);
	size_cabecera_tcp = TH_OFF(cabecera_tcp)*4;
	payload = (u_char *)(paquete + SIZE_ETHERNET + size_cabecera_ip + size_cabecera_tcp);
	size_payload = cabecera.len - 14 - size_cabecera_ip - size_cabecera_tcp;

	if (size_payload > 0) {
        if (cabecera_tcp->th_dport == 20480) { // 20480 es equivalente al 80.
            size_t encontrado1 = 0;
            size_t encontrado2 = 0;
            string sPayload(reinterpret_cast<char*>(payload));
            encontrado1 = sPayload.find("Host:");
            encontrado2 = sPayload.find("\r\n",encontrado1);

            if (encontrado1 < 1500) {
                Enlace *enlaceTemp = new Enlace(&(cabecera_ip->ip_src), cabecera_tcp->th_sport, &(cabecera_ip->ip_dst), cabecera_tcp->th_dport, conector);
                bool enlaceExiste = false;
                u_int posicion;
                if (vecEnl->size() > 0) {
                    for (u_int i = 0; i < vecEnl->size(); ++i) {
                        enlaceExiste = vecEnl->at(i)->esIgual(enlaceTemp);
                        if (enlaceExiste) {
                            posicion = i;
                            break;
                        }
                    }
                }
                if (enlaceExiste) {
            //		cout << "Enlace duplicado! Borrando enlace...   ";
                    delete enlaceTemp;
            //		cout << "Enlace borrado." << endl;
                }
                else {
                    vecEnl->push_back(enlaceTemp);

                    if (vecEnl->size() > 0) {
                        for (u_int i = 0; i < vecEnl->size(); ++i) {
                            enlaceExiste = vecEnl->at(i)->esIgual(enlaceTemp);
                            if (enlaceExiste) {
                                posicion = i;
                                break;
                            }
                        }
                    }
                    vecEnl->at(posicion)->agregarTrafico(cabecera.len);
                    string server = sPayload.substr(encontrado1 + 5, encontrado2 - encontrado1 - 5);
                    vecEnl->at(posicion)->setServidor(server);

            		stringstream convert;
                    string sqlString;
                    convert << "INSERT INTO tb_enlaces (create_date,ip_origen,ip_destino,puerto_tcp_dst,cantidad_trafico,nombre_servidor,estatus) VALUES (current_timestamp,'" << inet_ntoa(enlaceTemp->getIPorg());
                    convert << "','" << inet_ntoa(enlaceTemp->getIPfin()) << "'," << ntohs(enlaceTemp->getPuertoFin()) << "," << enlaceTemp->getTrafico() << ",'" << *(enlaceTemp->getServidor()) << "','" << *(enlaceTemp->getEstatus()) << "');"; // SELECT id FROM tb_enlaces ORDER BY 1 DESC LIMIT 1;";
                    sqlString = convert.str();
                    conector->ejecutarSQL(sqlString.c_str());
//                    enlaceTemp->setID(atoi(conector->getQuery(0,0)));
                }
                if (vecEnl->size() > 0) {
                        for (u_int i = 0; i < vecEnl->size(); ++i) {
                            enlaceExiste = vecEnl->at(i)->esIgual(enlaceTemp);
                            if (enlaceExiste) {
                                posicion = i;
                                break;
                            }
                        }
                    }
                vecEnl->at(posicion)->agregarTrafico(cabecera.len);
                string server = sPayload.substr(encontrado1 + 5, encontrado2 - encontrado1 - 5);
                vecEnl->at(posicion)->setServidor(server);
            }
		}
		else if (cabecera_tcp->th_dport == 47873) { // 47873 es equivalente al 443.
            ssl_payload_H = (sniff_ssl_H*)(paquete + SIZE_ETHERNET + size_cabecera_ip + size_cabecera_tcp);

            ssl_handshake_comp_methods_length = (u_char *)(paquete + SIZE_ETHERNET + size_cabecera_ip + size_cabecera_tcp + 46 + ntohs(ssl_payload_H->ssl_handshake_cipher_suites_length));

            ssl_payload_L = (sniff_ssl_L*)(paquete + SIZE_ETHERNET + size_cabecera_ip + size_cabecera_tcp + 46 + ntohs(ssl_payload_H->ssl_handshake_cipher_suites_length) + 1 + *ssl_handshake_comp_methods_length);

            const char *ssl_handshake_extensions_server_name = (char *)(paquete + SIZE_ETHERNET + size_cabecera_ip + size_cabecera_tcp + 46 + ntohs(ssl_payload_H->ssl_handshake_cipher_suites_length) + 1 + *ssl_handshake_comp_methods_length + 11);
            string server(ssl_handshake_extensions_server_name);

            if (ssl_payload_H->ssl_record_contentType == 0x16 && ssl_payload_H->ssl_handshake_type == 0x01 && ssl_payload_L->ssl_handshake_extension_type == 0 && !server.empty()) {
                server = server.substr(0,ntohs(ssl_payload_L->ssl_handshake_extensions_server_name_len));
                Enlace *enlaceTemp = new Enlace(&(cabecera_ip->ip_src), cabecera_tcp->th_sport, &(cabecera_ip->ip_dst), cabecera_tcp->th_dport, conector);
                bool enlaceExiste = false;
                u_int posicion;
                if (vecEnl->size() > 0) {
                    for (u_int i = 0; i < vecEnl->size(); ++i) {
                        enlaceExiste = vecEnl->at(i)->esIgual(enlaceTemp);
                        if (enlaceExiste) {
                            posicion = i;
                            break;
                        }
                    }
                }
                if (enlaceExiste) {
            //		cout << "Enlace duplicado! Borrando enlace...   ";
                    delete enlaceTemp;
            //		cout << "Enlace borrado." << endl;
                }
                else {
                    vecEnl->push_back(enlaceTemp);

                    if (vecEnl->size() > 0) {
                        for (u_int i = 0; i < vecEnl->size(); ++i) {
                            enlaceExiste = vecEnl->at(i)->esIgual(enlaceTemp);
                            if (enlaceExiste) {
                                posicion = i;
                                break;
                            }
                        }
                    }
                    vecEnl->at(posicion)->agregarTrafico(cabecera.len);
                    vecEnl->at(posicion)->setServidor(server);

            		stringstream convert;
                    string sqlString;
                    convert << "INSERT INTO tb_enlaces (ip_origen,ip_destino,puerto_tcp_dst,cantidad_trafico,nombre_servidor,estatus) VALUES ('" << inet_ntoa(enlaceTemp->getIPorg());
                    convert << "','" << inet_ntoa(enlaceTemp->getIPfin()) << "'," << ntohs(enlaceTemp->getPuertoFin()) << "," << enlaceTemp->getTrafico() << ",'" << *(enlaceTemp->getServidor()) << "','" << *(enlaceTemp->getEstatus()) << "');"; // SELECT id FROM tb_enlaces ORDER BY 1 DESC LIMIT 1;";
                    sqlString = convert.str();
                    conector->ejecutarSQL(sqlString.c_str());
//                    enlaceTemp->setID(atoi(conector->getQuery(0,0)));


                }
                if (vecEnl->size() > 0) {
                        for (u_int i = 0; i < vecEnl->size(); ++i) {
                            enlaceExiste = vecEnl->at(i)->esIgual(enlaceTemp);
                            if (enlaceExiste) {
                                posicion = i;
                                break;
                            }
                        }
                    }
                vecEnl->at(posicion)->agregarTrafico(cabecera.len);
                vecEnl->at(posicion)->setServidor(server);
            }
		}
	}
}







/*
				METODOS PARA MOSTRAR VALORES DE PROTOCOLOS TCP/IP



			cout << "************************************************************" << endl;
			cout << "La longitud del paquete capturado es: " << cabecera.len << endl;
			cout << "La longitud de la cabecera Ethernet siempre es 14." << endl;
			cout << "La longitud de la cabecera IP es: " << size_ip << endl;
			cout << "La longitud de la cabecera TCP es: " << size_tcp << endl;
			cout << "La longitud de los datos del paquete es: " << size_payload << endl << endl;

			cout << "MAC origen: ";
			for (int i = 0; i < 6; ++i)
				cout << setfill('0') << setw(2) << hex << (u_int)(cabecerapgadmin3_ethernet->ether_shost[i]) << ":";
			cout << dec << endl;

			cout << "MAC destino: ";
			for (int i = 0; i < 6; ++i)
				cout << setfill('0') << setw(2) << hex << (u_int)(cabecera_ethernet->ether_dhost[i]) << ":";
			cout << dec << endl;

			if (size_cabecera_ip >= 20 && size_cabecera_ip <= 60) {
				cout << "IP origen: " << inet_ntoa(cabecera_ip->ip_src) << endl;
				cout << "IP destino: " << inet_ntoa(cabecera_ip->ip_dst) << endl;
			}

			if (size_cabecera_tcp >= 20) {
				cout << "Puerto TCP origen: " << ntohs(cabecera_tcp->th_spoceTemp->getServidor()rt) << endl;
				cout << "Puerto TCP destino: " << ntohs(cabecera_tcp->th_dport) << endl;
				cout << "Número de secuencia TCP: " << hex << ntohl(cabecera_tcp->th_seq) << dec << endl << endl;
			}

			cout << "Carga: " << payload << endl; */
