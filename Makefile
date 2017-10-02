all:
	g++ -Wall -O2 main.cpp sources/dbConnector.cpp sources/dpi.cpp sources/enlace.cpp -Iinclude -I/opt/PostgreSQL/postgresql-9.6.5/src/interfaces/libpq/ -I/opt/PostgreSQL/postgresql-9.6.5/src/include/ -L/usr/local/pgsql/lib64/ -Llib/ -lpq -lpcap -llogfile -o bin/Release/dpi

main.o:
	g++ -Wall -O2 main.cpp -Iinclude/ -I/opt/PostgreSQL/postgresql-9.6.5/src/interfaces/libpq/ -I/opt/PostgreSQL/postgresql-9.6.5/src/include/ -Llib/ -llogfile -o obj/main.o

dbConnector.o:


dpi.o:


enlace.o:


objects:
