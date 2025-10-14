#include <iostream>        
#include <string>          
#include <fstream>         
#include <filesystem>      
#include <limits>          
#include <sstream>         

#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/statement.h>
#include <mysql_connection.h>
#include <mysql_driver.h>

using namespace std;
namespace fs = std::filesystem;


sql::mysql::MySQL_Driver* driver = nullptr;
sql::Connection* con = nullptr;
sql::Statement* stmt = nullptr;

void dbmsinsert(string metadata, string name, string extension, string encryption_time, string password);
std::string date() {
	using namespace std::chrono;
	auto now = system_clock::now();
	std::time_t t = system_clock::to_time_t(now);
	std::tm local_tm;
	localtime_s(&local_tm, &t); 
	std::ostringstream oss;
	oss << std::put_time(&local_tm, "%d-%m-%Y--%H:%M:%S");
	return oss.str();
}
long long seeder(string password) {
	long long seed = 0;
	for (char c : password) {
		seed = (seed * 131) + c;
	}
	return seed;
}

void xor_operation(vector<char>& bytes, int totalbytes, string password, long long position) {
	long long seed = seeder(password) + position;
	srand(seed);
	for (int i = 0; i < totalbytes; i++) {
		unsigned char key = rand() % 256;
		bytes[i] = bytes[i] ^ key;
	}
}

string encpassword(string password) {
	string salt = "hfalojwhd";
	string temp = password+salt;
	string result;
	int shift = 5;
	for (char ch : temp) {
		unsigned char c = static_cast<unsigned char>(ch);
		if (c >= 'a' && c <= 'z') {
			char out = 'a' + (c - 'a' + shift) % 26;
			result.push_back(out);
		}
		else if (c >= 'A' && c <= 'Z') {
			char out = 'A' + (c - 'A' + shift) % 26;
			result.push_back(out);
		}
		else if (c >= '0' && c <= '9') {
			char out = '0' + (c - '0' + shift) % 10;
			result.push_back(out);
		}
		else if (c >= 32 && c <= 126) {
			char out = 32 + (c - 32 + shift) % 95;
			result.push_back(out);
		}
		else {
			result.push_back(ch);
		}
	}
	return result;
}

void encrypt() {
	cout << "Enter file path: ";
	string cpath;
	string path;
	getline(cin, cpath);
	cpath.pop_back();
	cpath.erase(0, 1);
	//cout << path << endl;
	for (int i = 0; i < cpath.size(); i++) {
		if (cpath[i] == '\\') {
			path.push_back('\\');
			path.push_back('\\');
		}
		else {
			path.push_back(cpath[i]);
		}
	}
	if (fs::exists(path)) {
		cout << "File exists" << endl;
	}

	else {
		cout << "File doesn't exits" << endl;
		return;
	}

	int slashindex;
	for (int i = path.size() - 1; i >= 0; i--) {
		if (path[i] == '\\') {
			slashindex = i;
			break;
		}
	}

	int dotindex;
	for (int i = path.size() - 1; i >= 0; i--) {
		if (path[i] == '.') {
			dotindex = i;
			break;
		}
	}

	string outpath;
	for (int i = 0; i < slashindex; i++) {
		outpath.push_back(path[i]);
	}

	string filename;
	for (int i = slashindex + 1; i < dotindex; i++) {
		filename.push_back(path[i]);
	}

	string filetype;
	for (int i = dotindex + 1; i < path.size(); i++) {
		filetype.push_back(path[i]);
	}

	if (filetype == "enc") {
		cout << "File already encrypted!" << endl;
		return;
	}

	ifstream inFile(path, ios::binary);
	ofstream outFile(outpath + "\\" + filename + ".enc", ios::binary);

	string time = date();
	string metadata = path + '_' + time + '\n';
	cout << "metadata: " << metadata << endl;
	outFile.write(metadata.c_str(), metadata.size());

	string password;
	cout << "Enter a password: ";
	cin >> password;

	string ep = encpassword(password);

	const int bytesize = 64 * 1024;
	std::vector<char> bytes(bytesize);

	long long currentindex = 0;
	
	while (true) {
		inFile.read(bytes.data(), bytesize); 
		long long cbytesize = inFile.gcount();
		if (cbytesize == 0) {
			break;
		}

		xor_operation(bytes, cbytesize, password, currentindex);
		
		outFile.write(bytes.data(), cbytesize);
		currentindex += cbytesize;
	}

	inFile.close();
	outFile.close();

	cout << "Encryption done!" << endl;

	metadata.pop_back();
	dbmsinsert(metadata, filename, filetype, time, ep);
	fs::remove(path);

}

void decrypt() {
	cout << "Enter file path: ";
	string path;
	getline(cin, path);

	path.pop_back();
	path.erase(0, 1);
	
	if (fs::exists(path)) {
		cout << "File exists" << endl;
	}
	else {
		cout << "File doesn't exits" << endl;
		return;
	}

	ifstream inFile(path, ios::binary);
	if (!inFile.is_open()) {
		cout << "Failed to open file" << endl;
		return;
	}

	string metadata;
	getline(inFile, metadata);    
	
	cout << metadata << endl;
	
	sql::ResultSet* res = stmt->executeQuery(
		"SELECT `Name`, `Filetype`, `Password` FROM decrypted_data WHERE `Metadata`='" + metadata + "'"
	);

	if (!res->next()) {
		cout << "No matching record found in DB" << endl;
		inFile.close();
		return;
	}

	string filename = res->getString("Name");
	string filetype = res->getString("Filetype");
	string password = res->getString("Password");
	delete res;

	string inpassword;
	cout << "Enter a password: ";
	cin >> inpassword;
	string eip = encpassword(inpassword);
	if (eip != password) {
		cout << "Wrong passowrd!" << endl;
		return;
	}
	int slashindex;
	for (int i = path.size() - 1; i >= 0; i--) {
		if (path[i] == '\\') {
			slashindex = i;
			break;
		}
	}
	string outpath;
	for (int i = 0; i < slashindex; i++) {
		outpath.push_back(path[i]);
	}

	ofstream outFile(outpath + "\\" + filename + "." + filetype, ios::binary);

	const int bytesize = 64 * 1024;
	std::vector<char> bytes(bytesize);

	long long currentindex = 0;

	while (true) {
		inFile.read(bytes.data(), bytesize);
		long long cbytesize = inFile.gcount();
		if (cbytesize == 0) {
			break;
		}

		xor_operation(bytes, cbytesize, inpassword, currentindex);
		
		outFile.write(bytes.data(), cbytesize);
		currentindex += cbytesize;
	}

	inFile.close();
	outFile.close();
	cout << "Decryption done!" << endl;

	stmt->execute("DELETE FROM decrypted_data WHERE `Metadata`='" + metadata + "'");
	cout << "Deleted record from database." << endl;
	fs::remove(path);
}
void showinfo() {
	sql::ResultSet* res = stmt->executeQuery("SELECT * FROM decrypted_data");
	cout << "------------------------------------" << endl;
	while (res->next()) {
		cout << "Name: " << res->getString("Name") << endl;
		cout << "Filetype: " << res->getString("Filetype") << endl;
		cout << "Encryption-Time: " << res->getString("Encryption-Time") << endl;
		cout << "Password: " << res->getString("Password") << endl;
		cout << "------------------------------------" << endl;
	}
	delete res;

}
void dbmsinsert(string metadata,string name,string extension,string encryption_time,string password) {

	stmt->execute(
		"INSERT INTO decrypted_data (`Metadata`, `Name`, `Filetype`, `Encryption-Time`, `Password`) "
		"VALUES ('" + metadata + "','" + name + "','" + extension + "','" + encryption_time + "','" + password + "')"
	);
	cout << "Inserted a sample record." << endl;

}




void database() {
	driver = sql::mysql::get_mysql_driver_instance();
	con = driver->connect("tcp://127.0.0.1:3306", "root", "rahi");
	cout << "Connected to MySQL successfully!" << endl;

	stmt = con->createStatement();
	stmt->execute("create database if not exists project");
	stmt->execute("use project");
	stmt->execute(
		"create table if not exists decrypted_data ("
		"ID int auto_increment unique, "
		"Metadata varchar(500) not null, "
		"Name varchar(500), "
		"Filetype varchar(10), "
		"`Encryption-Time` varchar(100),"
		"Password varchar(500), "
		"primary key (metadata) "
		")"
	);
	cout << "Database and table are ready." << endl;
}

int main() {
	 database();
	 cout << "=================================" << endl;;
	 cout << " Stream Cipher Encryption System " << endl;;
	 cout << "=================================" << endl;;
	 while (true) {
	   cout << "1. Encrypt a File" << endl;
	   cout << "2. Decrypt a File" << endl;
	   cout << "3. See all decrypted file information" << endl;
	   cout << "4. Exit" << endl;
	   int a;
	   cout << "Enter your choice: ";
	   cin >> a;
	   cin.ignore(numeric_limits<streamsize>::max(), '\n');
	   if (a == 1) {
	     encrypt();
	   } else if (a == 2) {
	     decrypt();
	   } else if(a==3){
		   showinfo();
	   }
	   else {
		   break;
	   }
	 }
	 delete stmt;
	 delete con;
	return 0;
}
