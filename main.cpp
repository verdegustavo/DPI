// "main.cpp"

#include <iostream>
#include <unistd.h>
#include <cstdlib>
#include <dpi.h>
#include <enlace.h>
#include <vector>
#include <dbConnector.h>

int main (int argc, const char **argv) {
	if (getuid() == 0) {
		DPI inspector(argv[1], "port 80 or port 443");
		std::cout << "La interfaz a inspeccionar es: " <<  inspector.getInterfazCaptura() << std::endl;

        std::cout << "Conectando a la base de datos..." << std::endl;
		std::vector<Enlace*> vEnlaces;
		DBconnector conDB("user='dpiuser' password='dpiuser' dbname='dpidb' hostaddr='172.16.18.2' port='5432'");
//		DBconnector conDB("user='dpiuser' password='dpiuser' dbname='dpidb' hostaddr='127.0.0.1' port='5432'");

        if (conDB.isConnected()) {
            std::cout << std::endl << "Comenzando a capturar paquetes..." << std::endl;
            if (inspector.comenzarCaptura()) {
                for (int i = 0; i < atoi(argv[2]); ++i) {
                    inspector.parsePaquete(&vEnlaces, &conDB);
                    std::cout << "\rAnalizados: " << i + 1;
                }
            }
            else {
                std::cout << "Hubo un problema comenzando la captura." << std::endl;
            }

            std::cout << std::endl << std::endl << std::endl << "La cantidad de enlaces guardados son: " << vEnlaces.size() << std::endl;
            for (unsigned int i = 0; i < vEnlaces.size(); ++i)
                vEnlaces[i]->mostrarEnlace();

            for (unsigned int i = 0; i < vEnlaces.size(); ++i)
                delete vEnlaces[i];
            std::cout << "Memoria de enlaces limpia." << std::endl;

        }
	}
	else {
		std::cout << std::endl << "¡El usuario ejecutor del programa debe ser root! (solo root puede capturar)" << std::endl << std::endl;
		std::cout << std::endl << "Modo de uso: ./dpi <interfaz de red> <# de paquetes a analizar>" << std::endl
                  << "    Ejemplo: ./dpi eth0 1000" << std::endl << std::endl;
	}

	return 0;
}
