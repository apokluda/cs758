//==========================================================================
// Name        : hash_compare.cpp
// Author      : Alexander Pokluda
// Description : Compares the relative speed of the SHA-256 and BLAKE-256
//               hash functions
//==========================================================================

#include <cstdio>
#include <cstring>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <new>
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

extern "C"
{
	void blake256_hash(uint8_t *out, const uint8_t *in, uint64_t inlen);
}

extern const char* const str;
unsigned long const len = strlen(str);

void exit(const char* const msg)
{
	fputs(msg, stderr);
	exit(EXIT_FAILURE);
}

int main()
{
	// Open the video file
	int fd = open("ed_1024.ogv", O_RDONLY);
	if (fd == -1) exit("Unable to open file.");

	// Determine the file size
	struct stat sb;
	if (fstat(fd, &sb) == -1) exit("Unable to determine file size.");
	ssize_t fsize = sb.st_size;

	// Read the file into memory
	unsigned char* video = new(nothrow) unsigned char[fsize];
	if (!video) exit("Unable to allocate buffer.");
	if (read(fd, video, fsize) != fsize) exit("Error while reading file.");

	// Close the file
	close(fd);

	// ** Time OpenSSL's implementation of SHA-256 **
	cout << "Timing OpenSSL's implementation of SHA-256..." << endl;

	// Compute the amount of time required to hash a 2 KiB string
	// by hashing the string 1000 times and computing the average
	unsigned char hash[SHA256_DIGEST_LENGTH];
	time_pt start = now();
	for (int i = 0; i < STRING_ITERATIONS; ++i)
	{
		SHA256((const unsigned char* const)str, len, hash);
	}
	time_pt end = now();
	cout << "2 KiB string:\t" << (end-start) / STRING_ITERATIONS << endl;

	// Compute the amount of time required to hash a 45 MiB video
	// file by hashing the file 10 times and computing the average
	start = now();
	for (int i = 0; i < FILE_ITERATIONS; ++i)
	{
		SHA256(video, fsize, hash);
	}
	end = now();
	cout << "45 MiB file:\t" << (end - start) / FILE_ITERATIONS << endl;

	// ** Time the reference implementation of BLAKE-256 **
	cout << "Timing reference implementation of BLAKE-256..." << endl;

	// Compute the amount of time required to hash a 2 KiB string
	// by hashing the string 1000 times and computing the average
	start = now();
	for (int i = 0; i < STRING_ITERATIONS; ++i)
	{
		blake256_hash(hash, (const unsigned char* const)str, len);
	}
	end = now();
	cout << "2 KiB string:\t" << (end - start) / STRING_ITERATIONS << endl;

	// Compute the amount of time required to hash a 45 MiB video
	// file by hashing the file 10 times and computing the average
	start = now();
	for (int i = 0; i < FILE_ITERATIONS; ++i)
	{
		blake256_hash(hash, video, fsize);
	}
	end = now();
	cout << "45 MiB file:\t" << (end - start) / FILE_ITERATIONS << endl;

	delete [] video;
	return EXIT_SUCCESS;
}
