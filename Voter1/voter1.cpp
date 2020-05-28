#include "../Header.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <string>
#include <unistd.h>

using namespace std;
using namespace seal;


int verify_input(std::string str)
{
	//Definições de variáveis
	string delimiter = ",", delimiter_hifen = "-";
	string token, token_hifen;
	size_t pos = 0, pos_hifen = 0, comparer = 0;
	int number;
	float number_f;
	str.append(delimiter);

	while ((pos = str.find(delimiter)) != std::string::npos) {
		token = str.substr(0, pos);

		for (int i = 0; i < 2; i++) {
			pos_hifen = token.find(delimiter_hifen);

			if (pos_hifen == comparer){
				cout << "Formato de voto errado\n";
				return -1;
			}
			token_hifen = token.substr(0, pos_hifen);

			if (i == 0) {
				try{
					number_f = stof(token_hifen);
				}
				catch(std::exception& e){
					cout << "Formato de voto errado\n" ;
					return -1;
				}
				try{
					number = stoi(token_hifen);
				}
				catch(std::exception& e){
					cout << "Formato de voto errado\n" ;
					return -1;
				}
				if (number_f != (float)number){
					cout << "Formato de voto errado\n" ;
					return -1;
				}
			}
			if (i == 1) {
				try{
					number_f = stof(token_hifen);
				}
				catch(std::exception& e){
					cout << "Formato de voto errado\n" ;
					return -1;
				}
				try{
					number = stoi(token_hifen);
				}
				catch(std::exception& e){
					cout << "Formato de voto errado\n" ;
					return -1;
				}
				if (number_f != (float)number){
					cout << "Formato de voto errado\n" ;
					return -1;
				}
			}
			token.erase(0, pos_hifen + delimiter_hifen.length());
		}
		str.erase(0, pos + delimiter.length());
	}

}

int voter() {
	//Parametros do Encryptor
	EncryptionParameters parms(scheme_type::BFV);
	size_t poly_modulus_degree = 8192;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
	auto context = SEALContext::Create(parms);

	//Load das Keys
	ifstream stream_public_Key;

	PublicKey public_key;

	stream_public_Key.open("Voter1_Files/SEAL_public.key", ios::binary);

	public_key.load(context, stream_public_Key);

	//Criação do Encryptor
	Encryptor encryptor(context, public_key);
	BatchEncoder batch_encoder(context);

	size_t slot_count = batch_encoder.slot_count();
	size_t row_size = slot_count / 2;

	ofstream voto("Voter1_Files/vote.txt", ios::binary);

	//Definições de variáveis
	string str;
	string delimiter = ",", delimiter_hifen = "-";
	string token, token_hifen;
	size_t pos = 0, pos_hifen = 0;

	int j = 0, nmr_anos_bissextos = 11;

	Plaintext plain_matrix;

	int* votes_vector = new int[100];
	int* candi_vector = new int[100];

	string filename;

	vector<uint64_t> pod_matrix(slot_count, 0ULL);

	std::cout << "ID,candidate1-nr.votes,candidate2-nr.votes, ...,candidateN-nr.votes\n" << endl;
	cin >> str;

    while(verify_input(str) == -1)
    {
        cout << "Por favor, insira um formato válido...\n";
        cin >> str;
    }

	pos = str.find(delimiter);
	token = str.substr(0, pos);
	str.erase(0, pos + delimiter.length());

	time(0);
	voto << ((time(0) / 60 / 60)) % 24 << ":";  // hours
	voto << (time(0) / 60) % 60 << ":";  // minutes
	voto << (time(0)) % 60 << ",";  // seconds
	voto << (((time(0) / 60 / 60 / 24) - (time(0) / 60 / 60 / 24 / 365) * 365) - nmr_anos_bissextos) << ","; //dias no ano
	voto << (1970 + (time(0) / 60 / 60 / 24 / 365)) << ","; //ano

	voto << token << ",";

	while ((pos = str.find(delimiter)) != std::string::npos) {
		token = str.substr(0, pos);

		for (int i = 0; i < 2; i++) {
			pos_hifen = token.find(delimiter_hifen);
			token_hifen = token.substr(0, pos_hifen);

			if (i == 0) {
				candi_vector[j] = stoi(token_hifen);
			}
			if (i == 1) {
				votes_vector[j] = stoi(token_hifen);
			}
			token.erase(0, pos_hifen + delimiter_hifen.length());
		}
		str.erase(0, pos + delimiter.length());
		j++;
	}
	token = str.substr(0, pos);

	for (int i = 0; i < 2; i++) {
		pos_hifen = token.find(delimiter_hifen);
		token_hifen = token.substr(0, pos_hifen);

		if (i == 0) {
			candi_vector[j] = stoi(token_hifen);
		}
		if (i == 1) {
			votes_vector[j] = stoi(token_hifen);
		}
		token.erase(0, pos_hifen + delimiter_hifen.length());
	}
	str.erase(0, pos + delimiter.length());

	int miniPos, tempor, tempor_votes;

	for (int i = 0; i < j+1; i++)
	{
		miniPos = i;
		for (int k = i + 1; k < j+1; k++)
		{
			if (candi_vector[k] < candi_vector[miniPos]) //Change was here!
			{
				miniPos = k;
			}
		}

		tempor = candi_vector[miniPos];
		tempor_votes = votes_vector[miniPos];
		candi_vector[miniPos] = candi_vector[i];
		votes_vector[miniPos] = votes_vector[i];
		candi_vector[i] = tempor;
		votes_vector[i] = tempor_votes;

	}

	for (int i = 0; i < j+1; i++) {
		voto << candi_vector[i] << ",";
		pod_matrix[i] = votes_vector[i];
	}
	voto << "\n";

	batch_encoder.encode(pod_matrix, plain_matrix);

	//Next we encrypt the encoded plaintext.

	Ciphertext encrypted_matrix;
	encryptor.encrypt(plain_matrix, encrypted_matrix);

	encrypted_matrix.save(voto);

	voto.close();

	//deallocate the array
	delete[] votes_vector;
	delete[] candi_vector;

	return 0;
}

int main() {

    voter();

	system("openssl dgst --sha256 -sign Voter1_Files/Voter_private.key -out Voter1_Files/sign.sha256 Voter1_Files/vote.txt\n");

	system("cp Voter1_Files/Voter_cert.crt Voter1_Files/voter_cert.crt \n");

	system("mv Voter1_Files/vote.txt ../Ballot \n");
	sleep( 1 );
	system("mv Voter1_Files/sign.sha256 ../Ballot \n");
	sleep( 1 );
	system("mv Voter1_Files/voter_cert.crt ../Ballot \n");

}