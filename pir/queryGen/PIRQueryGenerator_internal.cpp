/* Copyright (C) 2014 Carlos Aguilar Melchor, Joris Barrier, Marc-Olivier Killijian
 * This file is part of XPIR.
 *
 *  XPIR is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  XPIR is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with XPIR.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "PIRQueryGenerator_internal.hpp"
#include "../crypto/NFLLWE.hpp"
/**
 *	Class constructor
 *	Params:
 *		- PIRParameters& pirParameters_ : PIRParameters reference shared with PIRClient.
 *		- crypto_ptr cryptoMethod_ 			: shared_pointer of Homomorphic crypto.
 **/
PIRQueryGenerator_internal::PIRQueryGenerator_internal(PIRParameters& pirParameters_,HomomorphicCrypto& cryptoMethod_) : 
	pirParams(pirParameters_),
	cryptoMethod(cryptoMethod_),
  queryBuffer("query_buffer"),
	mutex()
{}

/**
 * Generates asyncronously queries for each files.
 * Makes encrypted of 0 or 1.
 **/
uint64_t simple_power(uint32_t d, uint32_t n){
	uint64_t out = n;
	for(int i=1;i<d;i++)
		out*=n;	
	return out;	
}	

void PIRQueryGenerator_internal::generateQuery() 
{
  clock_t gq_start, gq_end; 
	gq_start = clock();
	size_t single_encrypted_val_size=0, size_se =0;

  double start = omp_get_wtime();
	coord = new unsigned int[pirParams.d]();

	computeCoordinates();
	for (unsigned int j = 0 ; j < pirParams.d ; j++)
	{
		for (unsigned int i = 0 ; i < pirParams.n[j] ; i++) 
		{

			if(j==0&&i==0){
				char *tmp = cryptoMethod.encrypt(0, j + 1);
				single_encrypted_val_size=strlen(tmp);
				size_se = cryptoMethod.getPublicParameters().getQuerySizeFromRecLvl(j+1) / (8);
				//std::cout << "ssasy_size: PIRQueryGenerator_internal: Generated a " << single_encrypted_val_size << " char(byte)-sized element query" << std::endl;
				std::cout << "measure_size_single:PIRQueryGenerator_internal:single_query_size:"<< size_se <<":bytes" << std::endl;
				std::cout << "measure_size:PIRQueryGenerator_internal:single_query_size:"<< (size_t)(size_se*(size_t)(simple_power(pirParams.d, pirParams.n[0]))) <<":bytes" << std::endl;
				}
				if (i == coord[j]) queryBuffer.push(cryptoMethod.encrypt(1, j + 1 ));
				else 
					queryBuffer.push(cryptoMethod.encrypt(0, j + 1));
	  }
  }
  double end = omp_get_wtime();
  gq_end = clock();
  delete[] coord;
  std::cout << "PIRQueryGenerator_internal: All the queries have been generated, total time is " << end - start << " seconds" << std::endl;
  std::cout << "consensgx1 : QueryGeneration time is " << (double)1000 * double(gq_end - gq_start)/(double)CLOCKS_PER_SEC << " ms" << std::endl; 
  std::cout << "measure_params:PIRQueryGenerator_internal:pirParams.d :" <<pirParams.d<< ":pirParams.alpha:"<<pirParams.alpha<<":pirParams.n[]:" ;  
	for (unsigned int i = 0 ; i < pirParams.d ; i++) 
		std::cout << pirParams.n[i] << ", ";
  std::cout<<std::endl << std::flush;
}

/**
 *	Compute coordinates of the chosen file.
 **/
void PIRQueryGenerator_internal::computeCoordinates()
{
	uint64_t x = chosenElement;

	for (unsigned int i = 0 ; i < pirParams.d ; i++)
	{
		coord[i] = x % pirParams.n[i];
		x /= pirParams.n[i];
	}
}

/**
 * Starts computation in a new thread
 **/
void PIRQueryGenerator_internal::startGenerateQuery()	
{
	queryThread = thread(&PIRQueryGenerator_internal::generateQuery, this);
}

uint64_t PIRQueryGenerator_internal::getChosenElement() 
{
	return chosenElement;
}

void PIRQueryGenerator_internal::setChosenElement( uint64_t _chosenElement ) 
{
	chosenElement = _chosenElement;
}

void PIRQueryGenerator_internal::setPIRParameters(PIRParameters& pirParams_)
{
  pirParams = pirParams_;
}

/**
 *	Join query thread if it's possible.
 **/
void PIRQueryGenerator_internal::joinThread() 
{
	if(queryThread.joinable()) queryThread.join();
}

void PIRQueryGenerator_internal::cleanQueryBuffer()
{
	while (!queryBuffer.empty())
		free(queryBuffer.pop_front());
}

PIRQueryGenerator_internal::~PIRQueryGenerator_internal() 
{
	joinThread();
  cleanQueryBuffer();
}

