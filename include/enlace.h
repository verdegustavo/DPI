// "enlace.h"
#pragma once

#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <dbConnector.h>

class Enlace {
private:
	in_addr ip_org, ip_fin;
	unsigned short /*puerto_TCP_org,*/ puerto_TCP_fin;
	unsigned long long cantd_trafico;
	bool SYN_flag_set, SYN_ACK_flag_set, ACK_flag_set, FIN_ACK_flag_set, RST_flag_set;
	std::string nombre_servidor;
	std::string estatus;
	unsigned long id_;
	DBconnector *conector_;

protected:


public:
	Enlace (const in_addr *ipOrg, unsigned short puertoOrg, const in_addr *ipDest, unsigned short puertoDest, DBconnector *conector);
	void TCPflagAnalisis(unsigned char flags);
	bool esIgual(Enlace *enlace);
	void agregarTrafico (unsigned short bytes);
	in_addr getIPorg();
	in_addr getIPfin();
//	unsigned short getPuertoOrg();
	unsigned short getPuertoFin();
	unsigned long long getTrafico();
	void mostrarEnlace();
	void setServidor(std::string &servidor);
	std::string* getServidor();
	void setID(unsigned long id);
	std::string* getEstatus();
};
