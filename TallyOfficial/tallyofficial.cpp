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

void rename_file(string file)
{
	string new_v("mv vote.txt ");
	new_v.append(file);
	new_v.append("\n");
	const char* new_vote = new_v.c_str();
	system(new_vote);
}
void remove_file(string file)
{
	string new_v("rm ");
	new_v.append(file);
	new_v.append("\n");
	const char* new_vote = new_v.c_str();
	system(new_vote);

}

std::string publicKey = load_s("/home/mariana/Desktop/Project/Administrator/root_CA/ter_publickey.pem");

RSA* createPublicRSA(std::string key) {
	RSA* rsa = NULL;
	BIO* keybio;
	const char* c_string = key.c_str();
	keybio = BIO_new_mem_buf((void*)c_string, -1);
	if (keybio == NULL) {
		return 0;
	}
	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	return rsa;
}

bool RSAVerifySignature(RSA* rsa,
	unsigned char* MsgHash,
	size_t MsgHashLen,
	const char* Msg,
	size_t MsgLen,
	bool* Authentic) {
	*Authentic = false;
	EVP_PKEY* pubKey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pubKey, rsa);
	EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

	if (EVP_DigestVerifyInit(m_RSAVerifyCtx, NULL, EVP_sha256(), NULL, pubKey) <= 0) {
		return false;
	}
	if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
		return false;
	}
	int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
	if (AuthStatus == 1) {
		*Authentic = true;
		EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
		return true;
	}
	else if (AuthStatus == 0) {
		*Authentic = false;
		EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
		return true;
	}
	else {
		*Authentic = false;
		EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
		return false;
	}
}
size_t calcDecodeLength(const char* b64input) {
	size_t len = strlen(b64input), padding = 0;

	if (b64input[len - 1] == '=' && b64input[len - 2] == '=') //last two chars are =
		padding = 2;
	else if (b64input[len - 1] == '=') //last char is =
		padding = 1;
	return (len * 3) / 4 - padding;
}

void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
	BIO* bio, * b64;

	int decodeLen = calcDecodeLength(b64message);
	*buffer = (unsigned char*)malloc(decodeLen + 1);
	(*buffer)[decodeLen] = '\0';

	bio = BIO_new_mem_buf(b64message, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	*length = BIO_read(bio, *buffer, strlen(b64message));
	BIO_free_all(bio);
}
bool verifySignature(std::string publicKey, std::string plainText, char* signatureBase64) {
	RSA* publicRSA = createPublicRSA(publicKey);
	unsigned char* encMessage;
	size_t encMessageLength;
	bool authentic;
	Base64Decode(signatureBase64, &encMessage, &encMessageLength);
	bool result = RSAVerifySignature(publicRSA, encMessage, encMessageLength, plainText.c_str(), plainText.length(), &authentic);
	return result & authentic;
}


int tally_op() {

	ifstream voto("vote.txt", ios::in | ios::binary);
	string* candi_vector = new string[100]; // primeira posição tem o votante
	string line, delimiter = ",", token, time, time_antigo, delimiter_time = ":";
	int N = 3; //nmr de candidatos que vem do administrador
	int counter = 0;
	size_t pos = 0;


	if (voto.is_open()) {
		string aux;
		getline(voto, line);
		while ((pos = line.find(delimiter)) != std::string::npos) {
			token = line.substr(0, pos);
			if (counter == 0) {
				time = token;
			}
			else if (counter == 1) {
				candi_vector[counter - 1] = token;
			}
			else {
				candi_vector[counter - 1] = token;
			}
			line.erase(0, pos + delimiter.length());
			counter++;
		}
		string voter = "vote";
		voter.append(candi_vector[0]);
		voter.append(".txt");

		cout << voter;

		ifstream old_vote(voter);
		if (old_vote.fail()) {

			rename_file(voter);
			old_vote.close();
			voto.close();

		}
		else
		{
			getline(old_vote, line);
			time_antigo = line.substr(0, line.find(delimiter));
			cout << time_antigo;

			int new_h, new_m, new_s, old_h, old_m, old_s;
			const char *time_ = time.c_str();
			const char *time_antigo_ = time_antigo.c_str();

			sscanf(time_, "%d:%d:%d", &new_h, &new_m, &new_s);
			sscanf(time_antigo_, "%d:%d:%d", &old_h, &old_m, &old_s);
			if(new_h < old_h)
			{
				remove_file("vote.txt");
				old_vote.close();
				voto.close();
				return -1;
			}
			else if(new_h > old_h)
			{
				remove_file(voter);
				rename_file(voter);

				old_vote.close();
				voto.close();
			}
			else
			{
				if(new_m < old_m)
				{
					remove_file("vote.txt");
					old_vote.close();
					voto.close();
					return -1;
				}
				else if (new_m > old_m)
				{
					remove_file(voter);
					rename_file(voter);

					old_vote.close();
					voto.close();
				}
				else
				{
					if(new_s < old_s)
					{
						remove_file("vote.txt");
						old_vote.close();
						voto.close();
						return -1;
					}
					else if (new_s > old_s)
					{
						remove_file(voter);
						rename_file(voter);

						old_vote.close();
						voto.close();
					}
					else
					{
						remove_file("vote.txt");
						old_vote.close();
						voto.close();
						return -1;
					}
				}
			}
		}

		if (counter - 2 != N){
			cout << "Voto inválido\n";
			remove_file("vote.txt");
			old_vote.close();
			voto.close();
			return -1;
		}
		string tempo = "temp";
		tempo.append(candi_vector[0]);
		tempo.append(".txt");

		ofstream temp(tempo, ios::binary);
		ifstream voto(voter, ios::in | ios::binary);
		string in;
		getline(voto,in);
		char c = voto.get();
		//const char* c_ = new char(c);
		while (voto.good()) {
			temp << c;
			c = voto.get();
		}
		temp.close();
	}
	else {
		// show message:
		std::cout << "Error opening file";
	}
}

bool calcs()
{
	int N = 3;
	ifstream temp1("temp1.txt");
	ifstream temp2("temp2.txt");
	ifstream temp3("temp3.txt");
	if (!temp1.fail() && !temp2.fail() && !temp3.fail())
	{
		//Parametros do Evaluator
		EncryptionParameters parms(scheme_type::BFV);
		size_t poly_modulus_degree = 8192;
		parms.set_poly_modulus_degree(poly_modulus_degree);
		parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
		parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
		auto context = SEALContext::Create(parms);
		shared_ptr context1 = context;

		ofstream checksumtxt1("checksum1.txt", ios::binary);
		ofstream checksumtxt2("checksum2.txt", ios::binary);
		ofstream checksumtxt3("checksum3.txt", ios::binary);
		ofstream resulttxt("result.txt", ios::binary);

		std::cout << "Set encryption parameters and print" << endl;
		print_parameters(context);

		Evaluator evaluator(context);

		ifstream stream_private_Key;
		SecretKey secret_key;
		stream_private_Key.open("/home/mariana/Desktop/Project/Administrator/Homomorphic_keys/SEAL_secretkey.key");
		secret_key.load(context1, stream_private_Key);
		ifstream stream_galloi_Key;
		GaloisKeys gal_keys;
		stream_galloi_Key.open("/home/mariana/Desktop/Project/Administrator/Homomorphic_keys/galois.key");
		gal_keys.load(context1, stream_galloi_Key);

		Decryptor decryptor(context, secret_key);
		BatchEncoder batch_encoder(context);

		ifstream weight1_("weight_1.txt", ios::binary);
		ifstream weight2_("weight_2.txt", ios::binary);
		ifstream weight3_("weight_3.txt", ios::binary);
		ifstream candi_("n_candidates.txt", ios::binary);

		KeyGenerator keygen(context);

		Ciphertext encrypted_matrix1, encrypted_matrix2, encrypted_matrix3, checksum1, checksum2, checksum3;
		Ciphertext weight1, weight2, weight3, candi, result;
		Ciphertext encrypted_matrix_rotated1, encrypted_matrix_rotated2, encrypted_matrix_rotated3;
		Ciphertext encrypted_matrix_weighted1, encrypted_matrix_weighted2, encrypted_matrix_weighted3;

		encrypted_matrix1.load(context1, temp1);
		encrypted_matrix2.load(context1, temp2);
		encrypted_matrix3.load(context1, temp3);

		Plaintext cenas;
		vector<uint64_t> pod_result;
		vector<uint64_t> pod_result1;
		vector<uint64_t> pod_result2;
		vector<uint64_t> pod_result3;
		vector<uint64_t> pod_result4;
		size_t slot_count = batch_encoder.slot_count();
		size_t row_size = slot_count/2;

		weight1.load(context1, weight1_);
		weight2.load(context1, weight2_);
		weight3.load(context1, weight3_);
		candi.load(context1, candi_);

		Plaintext cenas1, cenas2, cenas3;

		decryptor.decrypt(weight1, cenas1);
		batch_encoder.decode(cenas1, pod_result1);
		print_matrix(pod_result1, row_size);
		decryptor.decrypt(weight2, cenas2);
		batch_encoder.decode(cenas2, pod_result2);
		print_matrix(pod_result2, row_size);
		decryptor.decrypt(weight3, cenas3);
		batch_encoder.decode(cenas3, pod_result3);
		print_matrix(pod_result3, row_size);
		decryptor.decrypt(candi, cenas3);
		batch_encoder.decode(cenas3, pod_result4);
		print_matrix(pod_result3, row_size);


		evaluator.multiply(encrypted_matrix1, weight1, encrypted_matrix_weighted1);
		evaluator.multiply(encrypted_matrix2, weight2, encrypted_matrix_weighted2);
		evaluator.multiply(encrypted_matrix3, weight3, encrypted_matrix_weighted3);
		evaluator.add(encrypted_matrix_weighted1, encrypted_matrix_weighted2, result);
		evaluator.add_inplace(result, encrypted_matrix_weighted3);

		result.save(resulttxt);

		decryptor.decrypt(result, cenas);
		batch_encoder.decode(cenas, pod_result);
		print_matrix(pod_result, row_size);
		cout << "**************************************************************************";

		evaluator.rotate_rows(encrypted_matrix1, 1, gal_keys, encrypted_matrix_rotated1);
		evaluator.rotate_rows(encrypted_matrix2, 1, gal_keys, encrypted_matrix_rotated2);
		evaluator.rotate_rows(encrypted_matrix3, 1, gal_keys, encrypted_matrix_rotated3);

		evaluator.add(encrypted_matrix1, encrypted_matrix_rotated1, checksum1);
		evaluator.add(encrypted_matrix2, encrypted_matrix_rotated2, checksum2);
		evaluator.add(encrypted_matrix3, encrypted_matrix_rotated3, checksum3);

		for (int i = 1; i < N; i++) {
			evaluator.rotate_rows_inplace(encrypted_matrix_rotated1, 1, gal_keys);
			evaluator.add_inplace(checksum1, encrypted_matrix_rotated1);
			evaluator.rotate_rows_inplace(encrypted_matrix_rotated2, 1, gal_keys);
			evaluator.add_inplace(checksum2, encrypted_matrix_rotated2);
			evaluator.rotate_rows_inplace(encrypted_matrix_rotated3, 1, gal_keys);
			evaluator.add_inplace(checksum3, encrypted_matrix_rotated3);
		}

		evaluator.multiply_inplace(checksum1, candi);
		evaluator.multiply_inplace(checksum2, candi);
		evaluator.multiply_inplace(checksum3, candi);

		checksum1.save(checksumtxt1);
		checksum2.save(checksumtxt2);
		checksum3.save(checksumtxt3);


		// // // decryptor.decrypt(encrypted_matrix1, cenas);
		// // // batch_encoder.decode(cenas, pod_result);
		// // // print_matrix(pod_result, row_size);
		// // // decryptor.decrypt(encrypted_matrix2, cenas);
		// // // batch_encoder.decode(cenas, pod_result);
		// // // print_matrix(pod_result, row_size);
		// // // decryptor.decrypt(encrypted_matrix3, cenas);
		// // // batch_encoder.decode(cenas, pod_result);
		// // // print_matrix(pod_result, row_size);
		// // // Plaintext plain_1, plain_2, plain_3;

		// decryptor.decrypt(weight1, plain_1);
		// decryptor.decrypt(weight2, plain_2);
		// decryptor.decrypt(weight3, plain_3);

		// cout << plain_1.to_string() << "\n";
		// cout << plain_2.to_string() << "\n";
		// cout << plain_3.to_string() << "\n";

		cout << "**************************************\n\n\n";
		//Verificar com a multiplicacao antes
		//Para isso temos de correr de novo o administrator para verificar que encripta bem sem o batch, visto que é só um valor
		//fazer descriptacao logo no administrator a ver se o valor guardado está bem
		//ver as gal_keys que podem ser a origem dos numeros random
		//ver funcao do rotate

		//GaloisKeys gal_keys = keygen.galois_keys();

		decryptor.decrypt(checksum1, cenas);
		batch_encoder.decode(cenas, pod_result);
		print_matrix(pod_result, row_size);
		decryptor.decrypt(checksum2, cenas);
		batch_encoder.decode(cenas, pod_result);
		print_matrix(pod_result, row_size);
		decryptor.decrypt(checksum3, cenas);
		batch_encoder.decode(cenas, pod_result);
		print_matrix(pod_result, row_size);

/*

		checksum1.save(checksumtxt1);
		checksum2.save(checksumtxt2);
		checksum3.save(checksumtxt3);

		decryptor.decrypt(checksum1, cenas);
		batch_encoder.decode(cenas, pod_result);
		print_matrix(pod_result, row_size);
		decryptor.decrypt(checksum2, cenas);
		batch_encoder.decode(cenas, pod_result);
		print_matrix(pod_result, row_size);
		decryptor.decrypt(checksum3, cenas);
		batch_encoder.decode(cenas, pod_result);
		print_matrix(pod_result, row_size);*/
/*
		evaluator.multiply_inplace(encrypted_matrix, weight_voter);
		evaluator.add(encrypted_matrix, encrypted_matrix, result);
		evaluator.sub_inplace(result, encrypted_matrix);

		result.save(resulttxt);

		evaluator.add_inplace(result, encrypted_matrix);

		delete[] candi_vector;

		voto.close();*/

		//copy files to counter folder
    	system("cp checksum1.txt checksum2.txt checksum3.txt result.txt /home/mariana/Desktop/Project/Counter \n");

		return true;
	}
	else
	{
		return false;
	}
}

int main() {

//Check the signature of the vote, if signature fails remove the vote from the tally
ifstream sig("vote_sig.txt");

string str;

ostringstream ss;
ss << sig.rdbuf();
str = ss.str();

char* signature = new char[str.length() + 1];

strcpy(signature, str.c_str());

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

bool authentic = verifySignature(publicKey, plainText, signature);
if (authentic) {
	std::cout << "Authentic" << std::endl;
	//system("rm vote_sig.txt\n");
	//verify ID
	//tally_op();
}
else {
	std::cout << "Not Authentic" << std::endl;
	//remove_file("vote.txt");
}
tally_op();
calcs();
//Check if there is another vote in the tally from the same voter with a date previous to the current, if so discards the vote otherwise replaces the vote in the tally



//Computes homomorphically the checksum for each voteand adds it to an accumulator(see below)

//Compute homomorphically the result of the election(see below)

//Sends the election results and the checksum accumulator to the counter

	printf("TALLY\n");
}