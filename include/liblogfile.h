// liblogfile.h

#pragma once
#include <fstream>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

using namespace std;

class LogFile {
private:
	ofstream _archivo;
	time_t _tiempo;
	tm *_ahora;

public:
	LogFile(const char *nombre_log);
	~LogFile();
	void escribirLog(int short nivelLog, stringstream *mensaje); // 0: Info, 1: Warning, 2: Error!
};
