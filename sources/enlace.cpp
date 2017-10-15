// "enlace.cpp"

#include <enlace.h>
#include <iostream>
#include <sstream>

using namespace std;

Enlace::Enlace(const in_addr *ipOrg, unsigned short puertoOrg, const in_addr *ipDest, unsigned short puertoDest, DBconnector *conector) {
	ip_org = *ipOrg;
//	puerto_TCP_org = puertoOrg;
	ip_fin = *ipDest;
	puerto_TCP_fin = puertoDest;
	SYN_flag_set = false;
	SYN_ACK_flag_set = false;
	ACK_flag_set = false;
	FIN_ACK_flag_set = false;
	RST_flag_set = false;
	cantd_trafico = 0;
	nombre_servidor = "";
	estatus = "Inactivo";
	id_ = 0;
	conector_ = conector;
}

void Enlace::TCPflagAnalisis(unsigned char flags) {
	string estatusTemp;
	estatusTemp = estatus;
	switch (flags) {
		case 0x11:
			FIN_ACK_flag_set = true;
			break;
		case 0x02:
			SYN_flag_set = true;
			break;
		case 0x04:
			RST_flag_set = true;
			break;
		case 0x10:
			ACK_flag_set = true;
			break;
		case 0x12:
			SYN_ACK_flag_set = true;
			break;
	}

	if (ACK_flag_set && (!FIN_ACK_flag_set || !RST_flag_set))
		estatus = "\033[0;32mActivo\033[0m";

	if ((SYN_flag_set || SYN_ACK_flag_set) && !ACK_flag_set && !FIN_ACK_flag_set && !RST_flag_set)
		estatus = "\033[33mConectando...\033[0m";

	if (FIN_ACK_flag_set || RST_flag_set)
		estatus = "\033[36mTerminado\033[0m";


//	SI ESTATUS CAMBIA, ACTUALIZAR EN BASE DE DATOS
	if (estatusTemp.compare(estatus) != 0) {
/*		stringstream comando;
		comando << "UPDATE tb_enlaces SET cantidad_trafico = " << cantd_trafico << ", nombre_servidor = '" << nombre_servidor << "', estatus = '" << estatus << "' WHERE id = " << id_ << ";";
		conector_->ejecutarSQL(comando.str().c_str());*/
	}

}

bool Enlace::esIgual(Enlace *link) {
	if ( (link->getIPorg().s_addr == ip_org.s_addr &&
//	     link->getPuertoOrg() == puerto_TCP_org &&
	     link->getIPfin().s_addr == ip_fin.s_addr &&
	     link->getPuertoFin() == puerto_TCP_fin)
				||
	     (link->getIPorg().s_addr == ip_fin.s_addr &&
//	     link->getPuertoOrg() == puerto_TCP_fin &&
	     link->getIPfin().s_addr == ip_org.s_addr) // &&
//	     link->getPuertoFin() == puerto_TCP_org)
	    )
		return true;
	else
		return false;
}

void Enlace::agregarTrafico(unsigned short bytes) {
	cantd_trafico = cantd_trafico + bytes;
}

in_addr Enlace::getIPorg() {
	return ip_org;
}

in_addr Enlace::getIPfin() {
	return ip_fin;
}

/*unsigned short Enlace::getPuertoOrg() {
	return puerto_TCP_org;
}*/

unsigned short Enlace::getPuertoFin() {
	return puerto_TCP_fin;
}

unsigned long long Enlace::getTrafico() {
	return cantd_trafico;
}

void Enlace::mostrarEnlace() {
	cout << "++++++++++++++++++++++++++++++++++++++++++++++++" << endl;
	cout << inet_ntoa(ip_org) << /*":" << ntohs(puerto_TCP_org) <<*/ " <-> ";
	cout << inet_ntoa(ip_fin) << ":" << ntohs(puerto_TCP_fin) << " = ";
	cout << cantd_trafico << " bytes. Servidor: " << nombre_servidor// << endl;
	     << "Estado del enlace: " << estatus << endl;
}

void Enlace::setServidor(string &servidor) {
	nombre_servidor = servidor;
}

string* Enlace::getServidor() {
	return &nombre_servidor;
}

void Enlace::setID(unsigned long id) {
	id_ = id;
}

string* Enlace::getEstatus() {
	return &estatus;
}
