all:
	g++ -Wall -O2 main.cpp sources/dbConnector.cpp sources/dpi.cpp sources/enlace.cpp -Iinclude -I/opt/PostgreSQL/postgresql-9.6.5/src/interfaces/libpq/ -I/opt/PostgreSQL/postgresql-9.6.5/src/include/ -L/usr/local/pgsql/lib64/ -lpq -lpcap -o bin/Release/dpi
