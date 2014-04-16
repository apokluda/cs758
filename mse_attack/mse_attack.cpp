//==========================================================================
// Name        : mse_attack.cpp
// Author      : Alexander Pokluda
// Description : Computes SHA-1('req2', T_{info hash}) for all T_{info hash}
//               in the input file
//==========================================================================

#include <iostream>
#include <cstdio>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <boost/chrono.hpp>
#include <openssl/sha.h>

using namespace std;
using namespace boost;
using namespace boost::chrono;

typedef high_resolution_clock clock_type;
typedef clock_type::time_point time_pt;
inline clock_type::time_point now() { return clock_type::now(); }
typedef duration<double, ratio<1>> seconds_t;

struct infohash
{
	unsigned char bytes[SHA_DIGEST_LENGTH];
};

void hash_string_to_bytes(unsigned char* bytes, const char* str)
{
	const char* const end = str + 40;

	for (; str != end; ++str, ++bytes)
	{
		// Convert one nibble at a time (str and bytes array are big endian)
		if (*str - '0' < 10)
			*bytes = (*str - '0') << 4;
		else if (*str - 'A' < 26)
			*bytes = (*str - 'A' + 10) << 4;
		else if (*str - 'a' < 26)
			*bytes = (*str - 'a' + 10) << 4;
		else
			throw "invalid hash";

		++str;
		if (*str - '0' < 10)
			*bytes |= (*str - '0');
		else if (*str - 'A' < 26)
			*bytes |= (*str - 'A' + 10);
		else if (*str - 'a' < 26)
			*bytes |= (*str - 'a' + 10);
		else
			throw "invalid hash";
	}
}

void hash_bytes_to_string(char *str, const unsigned char* bytes)
{
	const char* end = str + 40;

	for (; str != end; ++str, ++bytes)
	{
		// Convert one nibble at a time (str and bytes array are big endian)
		unsigned char nibble = *bytes >> 4;
		if (nibble < 10)
			*str = '0' + nibble;
		else
			*str = 'a' - 10 + nibble;

		++str;
		nibble = *bytes & 0x0F;
		if (nibble < 10)
			*str = '0' + nibble;
		else
			*str = 'a' - 10 + nibble;
	}
}

void read_hashes(const char* c,  const char* end, vector<infohash>& hashes)
{
	cout << "Pre-processing file..." << endl;
	const time_pt time_start = now();

	size_t lnum = 0;
	for (; c != end; ++c)
	{
		if (*c == '\n')
		{
			++lnum;

			// Sanity check
			if (*(c - 1) == '|')
			{
				// this line does not have an info hash
				continue;
			}
			else if (*(c - 41) != '|')
			{
				cerr << "Error parsing line " << lnum
						<< ": invalid format" << endl;
				continue;
			}
			infohash hash;
			try {hash_string_to_bytes(hash.bytes, c - 40);}
			catch (...)
			{
				cerr << "Error parsing line " << lnum
						<< ": info hash is not 40 characters long or "
						"contains invalid characters" << endl;
				continue;
			}
			hashes.push_back(hash);
		}
	}

	const time_pt time_end = now();
	cout << "Identified " << hashes.size() << " torrent hashes. (took "
			<< duration_cast<seconds_t>(time_end-time_start) << ")" << endl;
}

infohash compute_hash(const infohash& h_in)
{
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, "req2", 4);
	SHA1_Update(&ctx, h_in.bytes, 20);
	infohash h_out;
	SHA1_Final(h_out.bytes, &ctx);
	return h_out;
}

int main(const int argc, const char* argv[])
{
	if (argc != 2)
	{
		cerr << "Usage: " << argv[0] << " torrent_index_file" << endl;
	}

	int retcode = EXIT_SUCCESS;
	int fd = -1;
	off_t fsize;
	void* addr = MAP_FAILED;

	try
	{
		// Open the file
		fd = open(argv[1], O_RDONLY);
		if (fd == -1) throw "Unable to open file.";

		// Determine the file size
		struct stat sb;
		if (fstat(fd, &sb) == -1) throw "Unable to determine file size.";
		fsize = sb.st_size;

		// Map the file into memory
		addr = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
		if (addr == MAP_FAILED) throw "Unable to mmap file.";

		// Read the hashes from the file
		vector<infohash> h_in;
		vector<infohash> h_out;
		h_in.reserve(2000000);
		read_hashes(static_cast<char*>(addr),
				static_cast<char*>(addr)+fsize, h_in);
		h_out.reserve(h_in.size());

		cout << "Computing H('req2' || T_{info hash}) "
				"for each T_{info_hash} in index..." << endl;
		const time_pt start = now();
		transform(h_in.begin(), h_in.end(), back_inserter(h_out),
				compute_hash);
		const time_pt end = now();
		const seconds_t elapsed = duration_cast<seconds_t>(end - start);
		cout << "Done. (took " << elapsed << "; "
				<< h_out.size()/elapsed.count() << " hashes per second)"
				<< endl;

		// This program was designed as a demonstration, so we simply print
		// a few of the computed hashes here. The following code could be
		// easily modified to output the computed hashes to a file.
		cout << "The first 10 H('req2' || T_{info hash}) -> T_{info hash} "
				"pairs are:" << endl;
		char h_str[41];
		for (vector<infohash>::const_iterator h_in_iter = h_in.begin(),
				h_out_iter = h_out.begin();
				h_in_iter != h_in.begin() + 10; ++h_in_iter, ++h_out_iter)
		{
			hash_bytes_to_string(h_str, h_out_iter->bytes);
			h_str[40] = '\0';
			cout << h_str << " -> ";
			hash_bytes_to_string(h_str, h_in_iter->bytes);
			h_str[40] = '\0';
			cout << h_str << '\n';
		}
		cout << endl;
	}
	catch (const char* err)
	{
		cerr << err << endl;
		retcode = EXIT_FAILURE;
	}
	catch (const std::bad_alloc&)
	{
		cerr << "Unable to allocate file buffer." << endl;
		retcode = EXIT_FAILURE;
	}
	catch (...)
	{
		cerr << "An unknown error occurred." << endl;
		retcode = EXIT_FAILURE;
	}

	if (fd != -1) close(fd);
	if (addr != MAP_FAILED) munmap(addr, fsize);

	return retcode;
}
