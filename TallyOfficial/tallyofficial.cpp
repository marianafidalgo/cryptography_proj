
#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#include "../Header.h"
#include "../Counter/counter.hpp"

#include <assert.h>

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
	f.close();


	return str;
}

void rename_file(string file)
{
	string new_v("mv TallyFiles/vote.txt ");
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

void remove_good()
{
	system("rm TallyFiles/sign.sha256\n");
	system("rm TallyFiles/voter_cert.crt\n");
	system("rm TallyFiles/voter_public.key\n");
}

void remove_bad(string file)
{
	system("rm TallyFiles/sign.sha256\n");
	system("rm TallyFiles/voter_cert.crt\n");
	system("rm TallyFiles/voter_public.key\n");
	string new_v("rm ");
	new_v.append(file);
	new_v.append("\n");
	const char* new_vote = new_v.c_str();
	system(new_vote);
}

void end_election()
{
	system("rm -r TallyFiles\n");
	system("rm -r ../Voter1/Voter1_Files\n");
	system("rm -r ../Voter2/Voter2_Files\n");
	system("rm -r ../Voter3/Voter3_Files\n");
	system("rm -r ../Administrator/Homomorphic_keys\n");

	system("rm -r ../Administrator/root_CA\n");
	system("rm  ../Counter/trustee1.txt\n");
	system("rm  ../Counter/trustee2.txt\n");
	system("rm  ../Counter/trustee3.txt\n");

	//CRIAR BALLOT TXT NOVO E MOVER
	ofstream ball("ballot.txt", ios::binary);
	ofstream end("end.txt", ios::binary);
	system("rm ../Ballot/ballot.txt\n");
	system("mv ballot.txt ../Ballot\n");
	system("mv end.txt ../Ballot\n");
}

int tally_op(int N, int vID) {

	ifstream voto("TallyFiles/vote.txt", ios::in | ios::binary);
	string* candi_vector = new string[100];
	string line, delimiter = ",", token, time_antigo, time, delimiter_time = ":", dia, ano;
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
				dia = token;
			}
			else if (counter == 2) {
				ano = token;
			}
			//Primeira posição contem votante
			else if (counter == 3) {
				candi_vector[counter - 3] = token;
				if(stoi(token) != vID)
				{
					cout << "Certificado não corresponde ao votante\n";
					remove_bad("TallyFiles/vote.txt");
					return -1;
				}
			}
			//Todas as outras posições contém os candidatos
			else {
				candi_vector[counter - 3] = token;
			}
			line.erase(0, pos + delimiter.length());
			counter++;
		}
		string voter = "TallyFiles/vote";
		voter.append(candi_vector[0]);
		voter.append(".txt");

		ifstream old_vote(voter);
		if (old_vote.fail()) {
			rename_file(voter);
			old_vote.close();
			voto.close();
		}
		else
		{
			getline(old_vote, line);
			time_antigo = line.substr(0, line.find(delimiter_time));

			int new_y, old_y, new_d, old_d, new_h, new_m, new_s, old_h, old_m, old_s;
			const char *time_ = time.c_str();
			const char *time_antigo_ = time_antigo.c_str();

			sscanf(time_, "%d:%d:%d,%d,%d", &new_h, &new_m, &new_s, &new_d, &new_y);
			sscanf(time_antigo_, "%d:%d:%d,%d,%d", &old_h, &old_m, &old_s, &old_d, &old_y);
			//Check if there is another vote in the tally from the same voter with a date previous to the current, if so discards the vote otherwise replaces the vote in the tally
			if(new_y < old_y)
			{
				remove_file("TallyFiles/vote.txt");
				old_vote.close();
				voto.close();
				return -1;
			}
			else if(new_y > old_y)
			{
				remove_file(voter);
				rename_file(voter);

			}
			else
			{
				if(new_d < old_d)
				{
					remove_file("TallyFiles/vote.txt");
					old_vote.close();
					voto.close();
					return -1;
				}
				else if(new_d > old_d)
				{
					remove_file(voter);
					rename_file(voter);

				}
				else
				{
					if(new_h < old_h)
					{
						remove_file("TallyFiles/vote.txt");
						old_vote.close();
						voto.close();
						return -1;
					}
					else if(new_h > old_h)
					{
						remove_file(voter);
						rename_file(voter);

					}
					else
					{
						if(new_m < old_m)
						{
							remove_file("TallyFiles/vote.txt");
							old_vote.close();
							voto.close();
							return -1;
						}
						else if (new_m > old_m)
						{
							remove_file(voter);
							rename_file(voter);

						}
						else
						{
							if (new_s > old_s)
							{
								remove_file(voter);
								rename_file(voter);

							}
							else
							{
								remove_file("TallyFiles/vote.txt");
								old_vote.close();
								voto.close();
								return -1;
							}
						}
					}
				}
			}
		}

		if (counter - 4 != N){
			cout << "Voto inválido: Numero de candidatos incorreto \n";
			remove_bad(voter);
			old_vote.close();
			voto.close();
			return -1;
		}
		for (int i = 1; i < N+1; i++) {
			if (stoi(candi_vector[i]) > N || stoi(candi_vector[i]) < 0) {
				cout << "Voto inválido: Votou em cadidatos que não existem\n";
				remove_bad(voter);
				old_vote.close();
				voto.close();
				return -1;
			}
			for (int j = 1; j < N+1; j++)
			{
				if (stoi(candi_vector[i]) == stoi(candi_vector[j]) && i != j)
				{
					cout << "Voto inválido: Votou mais que uma vez no mesmo candidato\n";
					remove_bad(voter);
					old_vote.close();
					voto.close();
					return -1;
				}
			}
		}

		string tempo = "TallyFiles/temp";
		tempo.append(candi_vector[0]);
		tempo.append(".txt");

		ofstream temp(tempo, ios::binary);
		ifstream voto(voter, ios::in | ios::binary);
		string in;
		getline(voto,in);
		char c = voto.get();
		while (voto.good()) {
			temp << c;
			c = voto.get();
		}
		temp.close();
		voto.close();
		delete[] candi_vector;

		//remove current voter trash files
		remove_good();
	}
	else {
		// show message:
		std::cout << "Erro a abrir o ficheiro";
		delete[] candi_vector;
		return -1;
	}
}

bool verify_sigs()
{
	system("openssl dgst --sha256 -verify TallyFiles/root_public.key -signature TallyFiles/w1.sha256 TallyFiles/weight_1.txt > TallyFiles/weight_v1.txt\n");
	system("openssl dgst --sha256 -verify TallyFiles/root_public.key -signature TallyFiles/w2.sha256 TallyFiles/weight_2.txt > TallyFiles/weight_v2.txt\n");
	system("openssl dgst --sha256 -verify TallyFiles/root_public.key -signature TallyFiles/w3.sha256 TallyFiles/weight_3.txt > TallyFiles/weight_v3.txt\n");
	system("openssl dgst --sha256 -verify TallyFiles/root_public.key -signature TallyFiles/n_candidates.sha256 TallyFiles/n_candidates.txt > TallyFiles/n_candidates_v.txt\n");
	system("openssl dgst --sha256 -verify TallyFiles/root_public.key -signature TallyFiles/result.sha256 TallyFiles/result.txt > TallyFiles/result_v.txt\n");
	string verified1 = load_s("TallyFiles/weight_v1.txt");
	string verified2 = load_s("TallyFiles/weight_v2.txt");
	string verified3 = load_s("TallyFiles/weight_v3.txt");
	string verified4 = load_s("TallyFiles/n_candidates_v.txt");
	string verified5 = load_s("TallyFiles/result_v.txt");

	if(verified1.compare("Verified OK\n") == 0 && verified2.compare("Verified OK\n") == 0 &&
	verified3.compare("Verified OK\n") == 0 && verified4.compare("Verified OK\n") == 0 && verified5.compare("Verified OK\n") == 0)
	{
		std::cout << "Authentic weights and number of candidates" << std::endl;
		return true;
	}
	else
	{
		std::cout << "Not authentic weights or candidates" << std::endl;
		//down with election
		cout << "Down with election\n";
		end_election();
		return false;
	}
}


int calcs(int N, int vID)
{
	int voters = 0;

	//Parametros do Evaluator
	EncryptionParameters parms(scheme_type::BFV);
	size_t poly_modulus_degree = 8192;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
	auto context = SEALContext::Create(parms);
	shared_ptr context1 = context;

	Evaluator evaluator(context);

	ifstream resulttxt("TallyFiles/result.txt", ios::binary);
	ifstream candi_("TallyFiles/n_candidates.txt", ios::binary);
	ofstream checksumacctxt("TallyFiles/checksumacc.txt", ios::binary);

	ifstream stream_private_Key;
	ifstream stream_galloi_Key;
	GaloisKeys gal_keys;
	stream_galloi_Key.open("../Administrator/Homomorphic_keys/galois.key");
	gal_keys.load(context1, stream_galloi_Key);

	BatchEncoder batch_encoder(context);

	Ciphertext encrypted_matrix1, encrypted_matrix2, encrypted_matrix3, checksum1, checksum2, checksum3;
	Ciphertext weight1, weight2, weight3, candi, result, checksumacc;
	Ciphertext encrypted_matrix_rotated1, encrypted_matrix_rotated2, encrypted_matrix_rotated3;
	Ciphertext encrypted_matrix_weighted1, encrypted_matrix_weighted2, encrypted_matrix_weighted3;
	Plaintext cenas;
	Plaintext cenas1, cenas2, cenas3;
	vector<uint64_t> pod_result;
	vector<uint64_t> pod_result1;
	vector<uint64_t> pod_result2;
	vector<uint64_t> pod_result3;
	vector<uint64_t> pod_result4;
	size_t slot_count = batch_encoder.slot_count();
	size_t row_size = slot_count/2;

	candi.load(context1, candi_);
	result.load(context1, resulttxt);

	ifstream temp1("TallyFiles/temp1.txt");
	ifstream temp2("TallyFiles/temp2.txt");
	ifstream temp3("TallyFiles/temp3.txt");

	evaluator.add(result, result, checksumacc);
	//Computes homomorphically the checksum for each voteand adds it to an accumulator
	//Compute homomorphically the result of the election(see below)
	if (!temp1.fail())
	{
		ifstream weight1_("TallyFiles/weight_1.txt", ios::binary);
		encrypted_matrix1.load(context1, temp1);
		weight1.load(context1, weight1_);
		evaluator.multiply(encrypted_matrix1, weight1, encrypted_matrix_weighted1);
		evaluator.add_inplace(result, encrypted_matrix_weighted1);
		evaluator.rotate_rows(encrypted_matrix1, 1, gal_keys, encrypted_matrix_rotated1);
		evaluator.add(encrypted_matrix1, encrypted_matrix_rotated1, checksum1);

		for (int i = 1; i < N; i++) {
			evaluator.rotate_rows_inplace(encrypted_matrix_rotated1, 1, gal_keys);
			evaluator.add_inplace(checksum1, encrypted_matrix_rotated1);
		}
		evaluator.multiply_inplace(checksum1, candi);
		evaluator.add_inplace(checksumacc, checksum1);

		voters++;

	}

	if(!temp2.fail())
	{
		ifstream weight2_("TallyFiles/weight_2.txt", ios::binary);
		encrypted_matrix2.load(context1, temp2);
		weight2.load(context1, weight2_);
		evaluator.multiply(encrypted_matrix2, weight2, encrypted_matrix_weighted2);
		evaluator.add_inplace(result, encrypted_matrix_weighted2);
		evaluator.rotate_rows(encrypted_matrix2, 1, gal_keys, encrypted_matrix_rotated2);
		evaluator.add(encrypted_matrix2, encrypted_matrix_rotated2, checksum2);
		for (int i = 1; i < N; i++) {
			evaluator.rotate_rows_inplace(encrypted_matrix_rotated2, 1, gal_keys);
			evaluator.add_inplace(checksum2, encrypted_matrix_rotated2);
		}
		evaluator.multiply_inplace(checksum2, candi);
		evaluator.add_inplace(checksumacc, checksum2);

		voters++;
	}

	if(!temp3.fail())
	{
		ifstream weight3_("TallyFiles/weight_3.txt", ios::binary);
		encrypted_matrix3.load(context1, temp3);
		weight3.load(context1, weight3_);
		evaluator.multiply(encrypted_matrix3, weight3, encrypted_matrix_weighted3);
		evaluator.add_inplace(result, encrypted_matrix_weighted3);
		evaluator.rotate_rows(encrypted_matrix3, 1, gal_keys, encrypted_matrix_rotated3);
		evaluator.add(encrypted_matrix3, encrypted_matrix_rotated3, checksum3);
		for (int i = 1; i < N; i++) {
			evaluator.rotate_rows_inplace(encrypted_matrix_rotated3, 1, gal_keys);
			evaluator.add_inplace(checksum3, encrypted_matrix_rotated3);
		}

		evaluator.multiply_inplace(checksum3, candi);
		evaluator.add_inplace(checksumacc, checksum3);

		voters++;
	}

	resulttxt.close();
	ofstream resultxt("TallyFiles/result.txt", ios::binary);
	result.save(resultxt);

	checksumacc.save(checksumacctxt);

	//Sends the election results and the checksum accumulator to the counter
	system("cp TallyFiles/checksumacc.txt ../Counter \n");
	system("cp TallyFiles/result.txt ../Counter \n");

	return voters;

}

int extract_pubkey_and_ID()
{
	string ID_str;
	//check which voter is
	ifstream cert("TallyFiles/voter_cert.crt");
	for (int i = 1; i <= 3; i++)
	{
		if (!cert.fail()) {

			system("openssl x509 -in TallyFiles/voter_cert.crt -noout -pubkey > TallyFiles/voter_public.key\n");
			system("openssl x509 -noout -subject -in TallyFiles/voter_cert.crt | sed -n 's/.*CN = \\([^,]*\\).*/\\1/p' > TallyFiles/id_voter.txt\n");
			ID_str = load_s("TallyFiles/id_voter.txt");
			if( stoi(ID_str) == i)
			{
				cert.close();
				system("rm TallyFiles/id_voter.txt");
				return i;
			}
		}

	}
	return -1;
}

bool extract_pubkey_and_ID_root_CA()
{
	string ID_str;
	//check root ca pub and id

	ifstream root("TallyFiles/root_ca.crt");
	if (!root.fail()) {

		system("openssl x509 -in TallyFiles/root_ca.crt -noout -pubkey > TallyFiles/root_public.key\n");
		system("openssl x509 -noout -subject -in TallyFiles/root_ca.crt | sed -n 's/.*CN = \\([^,]*\\).*/\\1/p' > TallyFiles/id_root.txt\n");
		ID_str = load_s("TallyFiles/id_root.txt");

		if(ID_str.compare("root\n") == 0)
		{
			root.close();
			system("rm TallyFiles/id_root.txt");
			return true;
		}
		else
		{
			root.close();
			//down with election
			cout << "CA inválido: não corresponde à root\n";
			end_election();
		}
	}
	return false;

}

int verify_n_cad()
{
	int N;
	system("openssl dgst --sha256 -verify TallyFiles/root_public.key -signature TallyFiles/nmr_c.sha256 TallyFiles/nmr_candi.txt > TallyFiles/nmr_candi_v.txt\n");

	string Nmr_C_str = load_s("TallyFiles/nmr_candi_v.txt");

	if(Nmr_C_str.compare("Verified OK\n")  == 0)
	{
		string n = load_s("TallyFiles/nmr_candi.txt");
		system("rm TallyFiles/nmr_candi_v.txt");
		N = stoi(n);
		return N;
	}
	else
	{
		cout << "Assinatura inválida: número de candidatos\n";
		//down with election
		end_election();
		return -1;
	}
}

int main() {

	int vID = -1, N = 0, voters = 0;

	vID = extract_pubkey_and_ID();

	if(extract_pubkey_and_ID_root_CA())
	{
		N = verify_n_cad();

		if(vID != -1 && N != 0)
		{
			system("openssl dgst --sha256 -verify TallyFiles/voter_public.key -signature TallyFiles/sign.sha256 TallyFiles/vote.txt > TallyFiles/verified.txt\n");
			string verified = load_s("TallyFiles/verified.txt");

			if(verified.compare("Verified OK\n") == 0)
			{
				system("rm TallyFiles/verified.txt");
				tally_op(N, vID);

				string answer;
				cout << "Pretende terminar a eleição? (sim ou nao) \n";
				cin >> answer;
				if(answer.compare("sim") == 0 && verify_sigs())
				{
					voters = calcs(N, vID);
					counter(N, voters);
					//down with election
					cout << "Fim da eleição\n";
					end_election();
					system("rm  ../Counter/result.txt\n");
					system("rm  ../Counter/checksumacc.txt\n");
					system("rm  ../Counter/SEAL_secretkey.key\n");

				}
			}
			else
			{
				//voto inválido
				cout << "Assinatura inválida do voto \n";
				string vote_R = "TallyFiles/vote";
				vote_R.append(to_string(vID));
				vote_R.append(".txt");
				remove_bad(vote_R);
			}
		}
	}

	exit(-1);

}