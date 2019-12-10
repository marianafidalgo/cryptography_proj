#include "../Header.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <assert.h>

#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")
#pragma comment(lib, "VC\\libeay32MD.lib")
#pragma comment(lib, "VC\\libeay32MDd.lib")
#pragma comment(lib, "VC\\libeay32MT.lib")
#pragma comment(lib, "VC\\libeay32MTd.lib")
#pragma comment(lib, "VC\\ssleay32MD.lib")
#pragma comment(lib, "VC\\ssleay32MDd.lib")
#pragma comment(lib, "VC\\ssleay32MT.lib")
#pragma comment(lib, "VC\\ssleay32MTd.lib")


using namespace std;
using namespace seal;

std::string load_s(string path)
{
	ifstream f(path);
	string str;
	if (f) {
		ostringstream ss;
		ss << f.rdbuf();
		str = ss.str();
	}
	//cout << str;
	return str;
}

std::string privateKey = load_s("/home/mariana/Desktop/Project/Administrator/root_CA/ter_private.key");

RSA* createPrivateRSA(std::string key) {
	RSA* rsa = NULL;
	const char* c_string = key.c_str();
	BIO* keybio = BIO_new_mem_buf((void*)c_string, -1);
	if (keybio == NULL) {
		return 0;
	}
	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	return rsa;
}


bool RSASign(RSA* rsa, const unsigned char* Msg, size_t MsgLen, unsigned char** EncMsg, size_t* MsgLenEnc) {
	EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
	EVP_PKEY* priKey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(priKey, rsa);
	if (EVP_DigestSignInit(m_RSASignCtx, NULL, EVP_sha256(), NULL, priKey) <= 0) {
		return false;
	}
	if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {
		return false;
	}
	if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <= 0) {
		return false;
	}
	*EncMsg = (unsigned char*)malloc(*MsgLenEnc);
	if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) {
		return false;
	}
	EVP_MD_CTX_destroy(m_RSASignCtx);
	return true;
}

void Base64Encode(const unsigned char* buffer,
	size_t length,
	char** base64Text) {
	BIO* bio, * b64;
	BUF_MEM* bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	*base64Text = (*bufferPtr).data;
}

char* signMessage(std::string privateKey, std::string plainText) {
	RSA* privateRSA = createPrivateRSA(privateKey);
	unsigned char* encMessage;
	char* base64Text;
	size_t encMessageLength;
	RSASign(privateRSA, (unsigned char*)plainText.c_str(), plainText.length(), &encMessage, &encMessageLength);
	Base64Encode(encMessage, encMessageLength, &base64Text);
	free(encMessage);
	return base64Text;
}

int voter() {
	//Parametros do Encryptor
	EncryptionParameters parms(scheme_type::BFV);
	size_t poly_modulus_degree = 8192;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
	auto context = SEALContext::Create(parms);

	print_line(__LINE__);
	std::cout << "Set encryption parameters and print" << endl;
	print_parameters(context);

	//Load das Keys
	ifstream stream_public_Key;
	ifstream stream_private_Key;

	PublicKey public_key;
	SecretKey secret_key;

	stream_public_Key.open("/home/mariana/Desktop/Project/Administrator/Homomorphic_keys/SEAL_public.key", ios::binary);
	stream_private_Key.open("/home/mariana/Desktop/Project/Administrator/Homomorphic_keys/SEAL_secretkey.key", ios::binary);

	public_key.load(context, stream_public_Key);
	secret_key.load(context, stream_private_Key);

	//Criação do Encryptor
	Encryptor encryptor(context, public_key);
	BatchEncoder batch_encoder(context);

	size_t slot_count = batch_encoder.slot_count();
	size_t row_size = slot_count / 2;
	std::cout << "Plaintext matrix row size: " << row_size << endl;

	ofstream voto("vote.txt", ios::binary);

	//Definições de variáveis
	string str;
	string delimiter = ",", delimiter_hifen = "-";
	string token, token_hifen;
	size_t pos = 0, pos_hifen = 0;

	int j = 0, nmr_anos_bissextos = 11;

	Plaintext plain_matrix;
	print_line(__LINE__);

	int* votes_vector = new int[100];
	int* candi_vector = new int[100];

	string filename;

	vector<uint64_t> pod_matrix(slot_count, 0ULL);

	std::cout << "ID,candidate1-nr.votes,candidate2-nr.votes, ...,candidateN-nr.votes\n" << endl;
	cin >> str;

	pos = str.find(delimiter);
	token = str.substr(0, pos);
	str.erase(0, pos + delimiter.length());

	time(0);
	voto << ((time(0) / 60 / 60)) % 24 << ":";  // hours
	voto << (time(0) / 60) % 60 << ":";  // minutes
	voto << (time(0)) % 60 << ",";  // seconds
	//voto << (((time(0) / 60 / 60 / 24) - (time(0) / 60 / 60 / 24 / 365) * 365) - nmr_anos_bissextos) << endl; //dias no ano
	//voto << (1970 + (time(0) / 60 / 60 / 24 / 365)) << endl; //ano

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

	cout << "Input plaintext matrix:" << endl;
	print_matrix(pod_matrix, row_size);

	cout << "Encode plaintext matrix:" << endl;
	batch_encoder.encode(pod_matrix, plain_matrix);

	/*
	Next we encrypt the encoded plaintext.
	*/
	Ciphertext encrypted_matrix;
	print_line(__LINE__);
	cout << "Encrypt plain_matrix to encrypted_matrix." << endl;
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
   	ofstream vote_sig;
	vote_sig.open("vote_sig.txt");

	ifstream vote("vote.txt");
	std::string line;
	std::string plainText="ola\n";
	/*while (getline( vote, line ))
	{
		plainText.append(line);
	}*/
	// getline( vote, line );

	// plainText.append(line);
	// cout << plainText;
	char* signature = signMessage(privateKey, plainText);

	vote_sig.write((char*)signature, 256);
	vote_sig.close();

}