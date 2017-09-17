// dbConnector.h
#pragma once

#include <libpq-fe.h>

class DBconnector {
private:
	const char *conninfo_;
	PGconn     *conn_;
	PGresult   *res_;

protected:


public:
	DBconnector(const char *conninfo);
	bool isConnected();
	void ejecutarSQL(const char *comando);
	char* getQuery(int fila, int columna);
	~DBconnector();
};

