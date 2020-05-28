#include "counter.hpp"

int counter(int N, int voters) {

	ifstream checksumacc_("../Counter/checksumacc.txt", ios::binary);
	ifstream results_("../Counter/result.txt", ios::binary);

	//Parametros do Decryptor
	EncryptionParameters parms(scheme_type::BFV);
	size_t poly_modulus_degree = 8192;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
	auto context = SEALContext::Create(parms);
	shared_ptr context1 = context;

	//Shamir shares

	string line;
	std::ofstream keycombined("../Counter/splitted.txt");
	std::ifstream in1("../Counter/trustee1.txt");
	std::ifstream in2("../Counter/trustee2.txt");
	std::ifstream in3("../Counter/trustee3.txt");

	getline( in1, line );
	keycombined << line << "\n" ;
	in1.close();
	getline( in2, line );
	keycombined << line << "\n" ;
	in2.close();
	getline( in3, line );
	keycombined << line << "\n" ;
	in3.close();
	keycombined.close();


	//Take the first 3 shares and combine them
	system("mv ../Counter/splitted.txt ~/.cargo/bin \n");
	system("cd ~/.cargo/bin \n cat splitted.txt | ./secret-share-combine > SEAL_secretkey.key \n");
	system("cd ~/.cargo/bin \n mv SEAL_secretkey.key /home/mariana/Desktop/Project/Counter \n rm splitted.txt \n");

	ifstream stream_private_Key;
	SecretKey secret_key;
	stream_private_Key.open("../Counter/SEAL_secretkey.key");
	secret_key.load(context, stream_private_Key);

	Decryptor decryptor(context, secret_key);
	BatchEncoder batch_encoder(context);

	Ciphertext encrypted_matrix;

	size_t slot_count = batch_encoder.slot_count();
	size_t row_size = slot_count / 2;
	vector<uint64_t> pod_result;

	Plaintext cenas;
	Ciphertext checksum, results;

	if (!checksumacc_.fail())
	{

		checksum.load(context1, checksumacc_);
		decryptor.decrypt(checksum, cenas);
		batch_encoder.decode(cenas, pod_result);
		//print_matrix(pod_result, row_size);
		if (pod_result[0] != N*N*voters) {
			cout << "Contagem de votos inválida \n";
			return -1;
		}
	}

	results.load(context1, results_);
	decryptor.decrypt(results, cenas);
	batch_encoder.decode(cenas, pod_result);
	//print_matrix(pod_result, row_size);

	int* largest_element = new int[100];
	int* winner_I = new int[100];
	largest_element[0] = pod_result[0];
	winner_I[0] = 0;
	int aux = 1;
	for(int i = 1; i < N; i++)
	{
		if(pod_result[i] > largest_element[0])
		{
			for(int j = 0; j < N; j++){
				largest_element[j] = 0;
				winner_I[j] = -1;
			}
			aux = 1;
			largest_element[0] = pod_result[i];
			winner_I[0] = i;
		}
		else if(pod_result[i] == largest_element[0])
		{
			largest_element[aux] = pod_result[i];
			winner_I[aux] = i;
			aux ++;
		}
	}
	if(aux == 1)
	{
		cout << "O vencedor é " << winner_I[0] +1 <<  " com "<< largest_element[0] << " votos!!!! \n";
	}
	else
	{
		cout << "Houve um empate entre: ";
		for(int i = 0; i < N; i++)
		{
			if (winner_I[i] != -1)
			{
				cout << winner_I[i] +1 << ",";
			}
		}
		cout << " com " << largest_element[0] << " votos!!!\n";
	}

}

