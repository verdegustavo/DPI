// "main.cpp"

#include <iostream>
#include <unistd.h>
#include <cstdlib>
#include <dpi.h>
#include <enlace.h>
#include <vector>
#include <dbConnector.h>
#include <fstream>

int main (int argc, const char **argv) {
	if (getuid() == 0) {
        std::string config_file, interfaz, stop;
        
        for (unsigned short i = 1; i <= argc; ++i) {
        std::string parametro;
        if (i != argc)
            parametro = argv[i];
        if ((parametro.compare("-c") == 0) or (parametro.compare("--config") == 0)) {
            config_file = argv[i+1];
        } else if ((parametro.compare("-i") == 0) or (parametro.compare("--interface") == 0)) {
            interfaz = argv[i+1];
        } else if ((parametro.compare("-s") == 0) or (parametro.compare("--stop") == 0)) {
            stop = argv[i+1];
        } else if ((parametro.compare("-h") == 0) or (parametro.compare("--help") == 0)) {
            std::cout << "Ayuda:\n\n\t-c, --config  <file>   insert DB configuration file.\n\t-i, --interface <interface>   insert interface name to be monitored.\n\t-s, --stop <num of packets>  insert the number of packets to be analized.\n\n";
            return -1;
        }
        }
            
        // Get database credentials from configuration file
        std::string db_user_name, db_password, db_name, db_host, db_port;
        std::ifstream configs (config_file, std::ifstream::in);
        std::string linea;

        for (unsigned short i = 0; std::getline(configs,linea); ++i) {
            std::size_t encontrado = linea.find("=");
            std::string configurador;
            configurador = linea.substr(0,encontrado);
            std::string valor;
            valor = linea.substr(encontrado + 2);
            if (configurador.compare("username ") == 0) {
                db_user_name = valor;
            } else if (configurador.compare("password ") == 0) {
                db_password = valor;
            } else if (configurador.compare("database name ") == 0) {
                db_name = valor;
            } else if (configurador.compare("host addr ") == 0) {
                db_host = valor;
            } else if (configurador.compare("port ") == 0) {
                db_port = valor;
            }
        }
		
		LogFile loggerMain("/home/gustavo/Desarrollo/DPI/v0.2/log/main.log");
        stringstream write2log;
		
        std::cout << "Conectando a la base de datos..." << std::endl;
        write2log << "Conectando a la base de datos...";
        loggerMain.escribirLog(0,&write2log);
		std::vector<Enlace*> vEnlaces;
        std::string DBConnectionString = "user='" + db_user_name + "' password='" + db_password + "' dbname='" + db_name + "' hostaddr='" + db_host + "' port='" + db_port + "'";
		DBconnector conDB(DBConnectionString.c_str());

        DPI inspector(interfaz.c_str(), "port 80 or port 443");
		std::cout << "La interfaz a inspeccionar es: " <<  inspector.getInterfazCaptura() << std::endl;
        write2log << "La interfaz a inspeccionar es: " <<  inspector.getInterfazCaptura();
        loggerMain.escribirLog(0,&write2log);
        
        if (conDB.isConnected()) {
            std::cout << std::endl << "Comenzando a capturar paquetes..." << std::endl;
            if (inspector.comenzarCaptura()) {
                for (int i = 0; i < atoi(stop.c_str()); ++i) {
                    inspector.parsePaquete(&vEnlaces, &conDB);
                    std::cout << "\rAnalizados: " << i + 1 << ". Enlaces en memoria: " << vEnlaces.size();
                }
            }
            else {
                std::cout << "Hubo un problema comenzando la captura." << std::endl;
                write2log << "Hubo un problema comenzando la captura.";
                loggerMain.escribirLog(2,&write2log);
            }

            std::cout << std::endl << std::endl << std::endl << "La cantidad de enlaces guardados son: " << vEnlaces.size() << std::endl;
            for (unsigned int i = 0; i < vEnlaces.size(); ++i)
                vEnlaces[i]->mostrarEnlace();

            for (unsigned int i = 0; i < vEnlaces.size(); ++i)
                delete vEnlaces[i];
            std::cout << "Memoria de enlaces limpia." << std::endl;
            write2log << "Memoria de enlaces limpia.";
            loggerMain.escribirLog(0,&write2log);
        } else {
            write2log << "Falló la conexión con la base de datos!";
            loggerMain.escribirLog(2,&write2log);
        }
	}
	else {
		std::cout << std::endl << "¡El usuario ejecutor del programa debe ser root! (solo root puede capturar)" << std::endl << std::endl;
		std::cout << "Ayuda:\n\n\t-c, --config  <file>   insert DB configuration file.\n\t-i, --interface <interface>   insert interface name to be monitored.\n\t-s, --stop <num of packets>  insert the number of packets to be analized.\n\n";
	}

	return 0;
}
