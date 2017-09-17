// dbConnector.cpp
#include <iostream>
#include <dbConnector.h>

using namespace std;

DBconnector::DBconnector(const char *conninfo) {
	if (conninfo != NULL)
		conninfo_ = conninfo;
	else
		conninfo_ = "dbname = postgres";

	conn_ = PQconnectdb(conninfo_);

	if (PQstatus(conn_) != CONNECTION_OK) {
		cout << "\033[1;31mFalló la conexión con la base de datos!\033[0m" << endl;
		cout << PQerrorMessage(conn_);
	}
	else {
		cout << "\033[1;32mConexión exitosa con la base de datos!\033[0m" << endl;
	}
}

DBconnector::~DBconnector() {
//	PQclear(res_);
//	PQfinish(conn_);
}

bool DBconnector::isConnected() {
    if (PQstatus(conn_) != CONNECTION_OK)
        return false;
	else
		return true;
}

void DBconnector::ejecutarSQL(const char *comando) {
	res_ = PQexec(conn_, comando);
}

char* DBconnector::getQuery(int fila, int columna) {
	return PQgetvalue(res_,fila,columna);
}
