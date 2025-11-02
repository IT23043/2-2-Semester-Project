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

//Make Database Connection
void database() {
	try {
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
	catch (sql::SQLException& e) {
		cerr << "MySQL Error (database setup): " << e.what() << 
			    " (MySQL error code: " << e.getErrorCode() << ")" << endl;
		exit(EXIT_FAILURE);
	}
}

void dbmsinsert(string metadata, string name, string extension, 
				string encryption_time, string password);

//Return Date and Time in String
string date() {
	using namespace std::chrono;
	auto now = system_clock::now();
	time_t t = system_clock::to_time_t(now);
	tm local_tm;
	localtime_s(&local_tm, &t); 
	ostringstream oss;
	oss << std::put_time(&local_tm, 
		"%d-%m-%Y--%H:%M:%S");
	return oss.str();
}

//generate Seeder
long long seeder(string password) {
	long long seed = 0;
	for (char c : password) {
		seed = (seed * 131) + c;
	}
	return seed;
}

//xor Operation
void xor_operation(vector<char>& bytes, 
	int totalbytes, string password, 
	long long position) {

	long long seed = seeder(password) + position;
	srand(seed);
	for (int i = 0; i < totalbytes; i++) {
		unsigned char key = rand() % 256;
		bytes[i] = bytes[i] ^ key;
	}
}

//Password Encryption with Salt and Ceaser Cipher 
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
string fixedpath(string& cpath) {
	if (cpath.back() == '"') {
		cpath.pop_back();
	}
		
	if (cpath.front() == '"') {
		cpath.erase(0, 1);
	}
	
	string path;
	for (int i = 0; i < cpath.size(); i++) {
		if (cpath[i] == '\\') {
			path.push_back('\\');
			path.push_back('\\');
		}
		else {
			path.push_back(cpath[i]);
		}
	}
	return path;
}
//Encryption Function
void encrypt() {
	cout << "\nEnter file path: ";
	string cpath;
	getline(cin, cpath);
	
	string path = fixedpath(cpath);
	//cout << path << endl;
	if (fs::exists(path)) {
		cout << "The file exists. Ready to Encrypt." << endl;
	}

	else {
		cout << "File doesn't exits" << endl;
		return;
	}

	fs::path p(path);

	string parentpath = p.parent_path().string();
	string filename = p.stem().string();
	string filetype = p.extension().string();
	filetype.erase(0, 1);
	
	if (filetype == "enc") {
		cout << "File already encrypted!" << endl;
		return;
	}

	cout <<"Parent path: " << parentpath << endl;
	cout << "Filename: " << filename << endl;
	cout << "Filetype: " << filetype << endl;
	ifstream inFile(path, ios::binary);
	
	string password;
	cout << "Enter a password: ";
	cin >> password;

	ofstream outFile(parentpath + "\\" + filename 
					+ ".enc", ios::binary);
	string time = date();
	string metadata = path + '_' + time + '\n';
	//cout << "metadata: " << metadata << endl;
	outFile.write(metadata.c_str(), metadata.size());

	string ep = encpassword(password);

	const int bytesize = 64 * 1024;
	vector<char> bytes(bytesize);

	long long currentindex = 0;
	
	while (true) {
		inFile.read(bytes.data(), bytesize); 
		long long cbytesize = inFile.gcount();
		if (cbytesize == 0) {
			break;
		}

		xor_operation(bytes, cbytesize, 
					ep, currentindex);
		
		outFile.write(bytes.data(), cbytesize);
		currentindex += cbytesize;
	}

	inFile.close();
	outFile.close();

	cout << "Encryption done!!" << endl;

	metadata.pop_back();

	dbmsinsert(metadata, filename, filetype, time, ep);

	fs::remove(path);

}

//Decryption Function
void decrypt() {
	cout << "\nEnter file path: ";
	string cpath;
	getline(cin, cpath);
	string path = fixedpath(cpath);
	if (fs::exists(path)) {
		cout << "The file exists." << endl;
	}
	else {
		cout << "File doesn't exists." << endl;
		return;
	}
	ifstream inFile(path, ios::binary);
	if (!inFile.is_open()) {
		cout << "Failed to open file." << endl;
		return;
	}
	string metadata;
	getline(inFile, metadata);
	fs::path p(path);
	string parentpath = p.parent_path().string();
	string extension = p.extension().string();
	extension.erase(0, 1);
	if (extension != "enc") {
		cout << "File is not in encrypted form." << endl;
		return;
	}
	//cout << metadata << endl;
	try {
		sql::ResultSet* res = stmt->executeQuery(
		"SELECT `Name`,`Filetype`,`Password` FROM decrypted_data WHERE `Metadata`='" 
		+ metadata + "'"
		);

		if (!res->next()) {
			cout << "No matching record found in Database." << endl;
			inFile.close();
			delete res;
			return;
		}
		cout << "Found matching record in Database." << endl;
		cout << "Ready to Decrypt." << endl;
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

		ofstream outFile(parentpath + "\\" + filename + "." 
			+ filetype, ios::binary);

		const int bytesize = 64 * 1024;
		std::vector<char> bytes(bytesize);

		long long currentindex = 0;

		while (true) {
			inFile.read(bytes.data(), bytesize);
			long long cbytesize = inFile.gcount();
			if (cbytesize == 0) {
				break;
			}

			xor_operation(bytes, cbytesize, eip, currentindex);

			outFile.write(bytes.data(), cbytesize);

			currentindex += cbytesize;
		}

		inFile.close();
		outFile.close();
		cout << "Decryption done!!" << endl;

		try {
			stmt->execute("delete from decrypted_data WHERE `Metadata`='" 
				+ metadata + "'");
			cout << "Deleted record from database." << endl<<endl;
		}
		catch (sql::SQLException& e) {
			cerr << "MySQL Error (delete): " << e.what() 
				<< " (MySQL error code: " << e.getErrorCode() << ")" << endl;
		}
		fs::remove(path);
	}
	catch (sql::SQLException& e) {
		cerr << "MySQL Error (query): " << e.what() 
			<< " (MySQL error code: " << e.getErrorCode() << ")" << endl;
		inFile.close();
	}
}

//Show records frommysql
void showinfo() {
	try {
		sql::ResultSet* res = stmt->executeQuery("SELECT * FROM decrypted_data");
		cout << "\n------------------------------------" << endl;
		bool hasData = false;
		while (res->next()) {
			hasData = true;
			cout << "Name: " << res->getString("Name") << endl;
			cout << "Filetype: " << res->getString("Filetype") << endl;
			cout << "Encryption-Time: " << res->getString("Encryption-Time") << endl;
			cout << "------------------------------------" << endl;
		}
		if (hasData==false) {
			cout << "No records found in the database." << endl;
			cout << "------------------------------------" << endl<<endl;
		}
		delete res;
	}
	catch (sql::SQLException& e) {
		cerr << "MySQL Error (showinfo): " << e.what() 
			<< " (MySQL error code: " << e.getErrorCode() << ")" << endl;
	}
}

//Insert Encrypted Data Information in Databases
void dbmsinsert(string metadata, string name, string extension, 
	string encryption_time, string password) {
	try {
		stmt->execute(
		"INSERT INTO decrypted_data(`Metadata`,`Name`,`Filetype`,`Encryption-Time`,`Password`)"
		"VALUES ('"+metadata+ "','"+name+"','"+extension+"','"+encryption_time+"','"+password+"')"
		);
		cout << "Inserted encrypted file information." << endl<<endl;
	}
	catch (sql::SQLException& e) {
		cerr << "MySQL Error (insert): " << e.what() 
			<< " (MySQL error code: " << e.getErrorCode() << ")" << endl;
	}
}


int main() {
	database();
	 cout << "=================================" << endl;;
	 cout << " Stream Cipher Encryption System " << endl;;
	 cout << "=================================" << endl;;
	 while (true) {
	   cout << "1. Encrypt a File" << endl;
	   cout << "2. Decrypt a File" << endl;
	   cout << "3. See all encrypted file information" << endl;
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
