//==========================================================================
// Name        : aes_time.cpp
// Author      : Alexander Pokluda
// Description : Measures how long it takes to encrypt a 2 KiB text string
//               and 45 MiB video file using 256-bit AES in CBC mode
//==========================================================================

#include <cstring>
#include <cassert>
#include <openssl/aes.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <vector>
#include <iostream>
#include <iomanip>
#include <boost/chrono.hpp>

const int STRING_ITERATIONS = 1000;
const int FILE_ITERATIONS = 10;

using namespace std;
using namespace boost;
using namespace boost::chrono;

typedef high_resolution_clock clock_type;
typedef clock_type::time_point time_pt;
inline clock_type::time_point now() { return clock_type::now(); }
typedef duration<double, ratio<1>> seconds_t;

extern const char* const str;
unsigned long const len = strlen(str);

void exit(const char* const msg)
{
	fputs(msg, stderr);
	exit(EXIT_FAILURE);
}

const int AES_256_KEY_LEN = 32;

typedef unsigned char byte;
typedef vector<byte> buf_t;

inline const byte* to_bytes(const void* ptr)
{
	return reinterpret_cast<const byte*>(ptr);
}

inline byte* to_bytes(void* ptr)
{
	return reinterpret_cast<byte*>(ptr);
}

inline const byte* to_bytes(const buf_t& buf)
{
	return buf.data();
}

inline byte* to_bytes(buf_t& buf)
{
	return buf.data();
}

inline const char* to_str(const buf_t& buf)
{
	return reinterpret_cast<const char*>(buf.data());
}

// Print the first 20 bytes of buffer
std::ostream &operator<<(std::ostream &out, const buf_t& buf)
{
	out << hex << setfill('0');
	buf_t::const_iterator i = buf.begin();
	const buf_t::const_iterator end = (buf.end()-i>10 ? i+10 : buf.end());
	for (; i != end; ++i)
	{
		out << setw(2) << static_cast<unsigned>(*i);
	}
	if (end != buf.end())
	{
		out << "...";
	}
	return out << dec;
}

const byte* key_data = to_bytes("Really simple and insecure key.");
const byte ivec_data[AES_BLOCK_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

template <size_t multiple>
inline size_t round_up(const size_t len)
{
	if (len % multiple == 0) return len;
	else return ((len / multiple) + 1) * multiple;
}

void OpenSSL_AES_256_CBC_Encrypt(const byte* plaintext, byte* ciphertext,
		const size_t len, const byte* ivec_data, const byte* key_data)
{
	byte ivec[AES_BLOCK_SIZE];
	memcpy(ivec, ivec_data, AES_BLOCK_SIZE);

	AES_KEY e_key;
	AES_set_encrypt_key(key_data, 256, &e_key);
	AES_cbc_encrypt(plaintext, ciphertext, len, &e_key, ivec, AES_ENCRYPT);
}

void OpenSSL_AES_256_CBC_Decrypt(byte* plaintext, const byte* ciphertext,
		const size_t len, const byte* ivec_data, const byte* key_data)
{
	assert(len % AES_BLOCK_SIZE == 0);

	byte ivec[AES_BLOCK_SIZE];
	memcpy(ivec, ivec_data, AES_BLOCK_SIZE);

	AES_KEY d_key;
	AES_set_decrypt_key(key_data, 256, &d_key);
	AES_cbc_encrypt(ciphertext, plaintext, len, &d_key, ivec, AES_DECRYPT);
}

int main()
{
	try
	{
		// Open the video file
		int fd = open("ed_1024.ogv", O_RDONLY);
		if (fd == -1) exit("Unable to open file.");

		// Determine the file size
		struct stat sb;
		if (fstat(fd, &sb) == -1) exit("Unable to determine file size.");
		ssize_t fsize = sb.st_size;

		// Read the file into memory
		buf_t video;
		video.resize(fsize);
		if (read(fd, to_bytes(video), fsize) != fsize)
			exit("Error while reading file.");

		// Close the file
		close(fd);

		// ** Time OpenSSL's implementation of 256-bit AES **
		cout << "Timing OpenSSL's implementation of 256-bit AES..." << endl;

		assert(fsize >= static_cast<ssize_t>(len));
		const size_t encrypted_video_len = round_up<AES_BLOCK_SIZE>(fsize);
		const size_t encrypted_str_len = round_up<AES_BLOCK_SIZE>(len);
		buf_t ciphertext, plaintext;

		// Compute the amount of time required to encrypt and decrypt
		// a 2 KiB string by averaging 1000 trials
		ciphertext.resize(encrypted_str_len);
		time_pt start = now();
		for (int i = 0; i < STRING_ITERATIONS; ++i)
		{
			OpenSSL_AES_256_CBC_Encrypt(to_bytes(str), to_bytes(ciphertext),
					len, ivec_data, key_data);
		}
		time_pt end = now();
		string start_str(str, 10);
		start_str += "...";
		cout << "Starting string:\t\t\"" << start_str
				<< "\"\nEncrypted string data:\t\t" << ciphertext
				<< "\nTime to encrypt 2 KiB string:\t"
				<< (end-start) / STRING_ITERATIONS << endl;

		plaintext.resize(encrypted_str_len);
		start = now();
		for (int i = 0; i < STRING_ITERATIONS; ++i)
		{
			OpenSSL_AES_256_CBC_Decrypt(to_bytes(plaintext),
					to_bytes(ciphertext), encrypted_str_len, ivec_data,
					key_data);
		}
		end = now();
		string end_str(to_str(plaintext), 10);
		end_str += "...";
		cout << "Decrypted string data:\t\t" << plaintext
				<< "\nEnding String:\t\t\t\"" << end_str
				<< "\"\nTime to decrypt 2 KiB string:\t"
				<< (end-start) / STRING_ITERATIONS << endl;

		// Compute the amount of time required to encrypt and decrpyt
		// a 45 MiB video by averaging 10 trials
		ciphertext.resize(encrypted_video_len);
		start = now();
		for (int i = 0; i < FILE_ITERATIONS; ++i)
		{
			OpenSSL_AES_256_CBC_Encrypt(to_bytes(video),
					to_bytes(ciphertext), fsize, ivec_data, key_data);
		}
		end = now();
		double duration = duration_cast<seconds_t>(end - start).count() /
				FILE_ITERATIONS;
		double rate = (fsize / duration) * 8 / 1000000; // Mbit/sec
		cout << "\nEncrypted video data:\t\t" << ciphertext
				<< "\nTime to encrypt 45 MiB video:\t" << duration
				<< " seconds (" << rate << " Mbit/sec)" << endl;

		plaintext.resize(encrypted_video_len);
		start = now();
		for (int i = 0; i < FILE_ITERATIONS; ++i)
		{
			OpenSSL_AES_256_CBC_Decrypt(to_bytes(plaintext),
					to_bytes(ciphertext), encrypted_video_len, ivec_data,
					key_data);
		}
		end = now();
		duration = duration_cast<seconds_t>(end - start).count() /
				FILE_ITERATIONS;
		rate = (fsize / duration) * 8 / 1000000; // Mbit/sec
		cout << "Decrypted video data:\t\t" << plaintext
				<< "\nTime to decrypt 45 MiB video:\t" << duration
				<< " seconds (" << rate << " Mbit/sec)" << endl;

		// ** Time direct memory copy for comparison with AES **
		cout << "\nTiming direct memory copy..." << endl;

		// Compute the amount of time required to copy
		// a 2 KiB string by averaging 1000 trials
		start = now();
		for (int i = 0; i < STRING_ITERATIONS; ++i)
		{
			memcpy(to_bytes(ciphertext), to_bytes(str), len);
		}
		end = now();
		cout << "Time to copy 2 KiB string:\t"
				<< (end-start) / STRING_ITERATIONS << endl;

		// Compute the amount of time required to copy
		// a 45 MiB video averaging 10 trials
		start = now();
		for (int i = 0; i < FILE_ITERATIONS; ++i)
		{
			memcpy(to_bytes(ciphertext), to_bytes(video), fsize);
		}
		end = now();
		duration = duration_cast<seconds_t>(end - start).count() /
				FILE_ITERATIONS;
		rate = (fsize / duration) * 8 / 1000000; // Mbit/sec
		cout << "\nTime to copy 45 MiB video:\t" << duration
				<< " seconds (" << rate << " Mbit/sec)" << endl;

		return EXIT_SUCCESS;
	}
	catch (const std::bad_alloc&)
	{
		cerr << "Error allocating buffer." << endl;
		return EXIT_FAILURE;
	}
}
