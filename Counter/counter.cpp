#include "../Header.h"
#include <string>
#include <iostream>


using namespace seal;
using namespace std;

int main() {

	int N = 3;

	//Parametros do Decryptor
	EncryptionParameters parms(scheme_type::BFV);
	size_t poly_modulus_degree = 8192;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
	auto context = SEALContext::Create(parms);
	shared_ptr context1 = context;

	ifstream stream_private_Key;
	SecretKey secret_key;
	stream_private_Key.open("/home/mariana/Desktop/Project/Administrator/Homomorphic_keys/SEAL_secretkey.key");
	secret_key.load(context, stream_private_Key);

	Decryptor decryptor(context, secret_key);
	BatchEncoder batch_encoder(context);

	size_t slot_count = batch_encoder.slot_count();
	size_t row_size = slot_count / 2;
	vector<uint64_t> pod_result;
	Plaintext cenas;
	Ciphertext checksum1, checksum2, checksum3, results;

	ifstream checksum1_("checksum1.txt", ios::binary);
	ifstream checksum2_("checksum2.txt", ios::binary);
	ifstream checksum3_("checksum3.txt", ios::binary);
	
	checksum1.load(context1, checksum1_);
	checksum2.load(context1, checksum2_);
	checksum3.load(context1, checksum3_);

	Ciphertext encrypted_matrix;

	decryptor.decrypt(checksum1, cenas);
	batch_encoder.decode(cenas, pod_result);
	print_matrix(pod_result, row_size);
	if (pod_result[0] != N*N) {
		cout << "At least one vote was invalid\n";
		exit(0);
	}
	decryptor.decrypt(checksum2, cenas);
	batch_encoder.decode(cenas, pod_result);
	print_matrix(pod_result, row_size);
	if (pod_result[0] != N*N) {
		cout << "At least one vote was invalid\n";
		exit(0);
	}
	decryptor.decrypt(checksum3, cenas);
	batch_encoder.decode(cenas, pod_result);
	print_matrix(pod_result, row_size);
	if (pod_result[0] != N*N) {
		cout << "At least one vote was invalid\n";
		exit(0);
	}

	ifstream results_("result.txt", ios::binary);
	results.load(context1, results_);

	decryptor.decrypt(results, cenas);
	batch_encoder.decode(cenas, pod_result);
	print_matrix(pod_result, row_size);


	int largest_element = pod_result[0];
	int winner_I = 0;
	for(int i = 1; i < N; i++)
	{
		if(pod_result[i] > largest_element)
		{
			largest_element = pod_result[i];
			winner_I = i;
		}
	}

		cout << "The winner is " << winner_I +1 <<  " with "<< largest_element << " votes!!!! \n";

}

