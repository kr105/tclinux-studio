//
// Copyright (c) 2019-2023 Carlos Pizarro <kr105@kr105.com>
// Copyright (c) 2019 [anp/hsw] <sysop@880.ru>
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#if defined(_WIN32) || defined(_WIN64)
#include <Winsock2.h>
#else
#include <arpa/inet.h>
#endif

#define TCL_MAGIC 0x32524448
#define TCL_HEADER_SIZE 0x100

typedef enum { HELP, TEST, EXTRACT, CREATE } runmode;

struct tcl_header {
	uint32_t magic;					// HDR2
	uint32_t lenheader;				// Length of header
	uint32_t lenfile;				// Length of the entire file
	uint32_t crc32;					// CRC32 without the header
	uint8_t version[32];			// Version base ?
	uint8_t versioncustom[32];		// Version customized ?
	uint32_t lenkernel;				// Length of kernel
	uint32_t lenrootfs;				// Lenght of rootfs
	uint32_t unk1;					// ?
	uint8_t devicemodel[32];		// Device model
	uint32_t decompressaddr;		// Decompress address for kernel
	uint32_t reserved[32];			// ?
};

// ========================================================================

/* Copyright (C) 1986 Gary S. Brown.  You may use this program, or
   code or tables extracted from it, as desired without restriction. */

uint32_t crc_32_tab[] = { /* CRC polynomial 0xedb88320 */
0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

#define UPDC32(octet,crc) (crc_32_tab[((crc) ^ (octet)) & 0xff] ^ ((crc) >> 8))

uint32_t crc32buf(char *buf, size_t len)
{
	uint32_t crc;

	crc = 0xFFFFFFFF;

	for (; len; --len, ++buf)
	{
		crc = UPDC32(*buf, crc);
	}

	return crc;
}
// ========================================================================

int checktcl(FILE* tclfile, struct tcl_header *headerout)
{
	char *filebody = NULL;
	size_t filesize = 0;
	size_t bodysize = 0;
	size_t readsize = 0;
	size_t bytesread = 0;
	struct tcl_header header;
	uint32_t crc32 = 0;

	// Get file size
	fseek(tclfile, 0L, SEEK_END);
	filesize = ftell(tclfile);
	rewind(tclfile);

	if (filesize < TCL_HEADER_SIZE) {
		printf("File size too small.\n");
		return 0;
	}

	// Read the header
	readsize = fread((void *)&header, 1, TCL_HEADER_SIZE, tclfile);

	if (readsize != TCL_HEADER_SIZE) {
		printf("Fail reading file header.\n");
		return 0;
	}

	// Check filesize in header with actual filesize
	if (ntohl(header.lenfile) != filesize) {
		printf("Header file size doesn't match with the actual file size.\n");
		return 0;
	}

	// Check if sum of all sizes in header match the actual filesize
	if ((ntohl(header.lenkernel) + ntohl(header.lenheader) + ntohl(header.lenrootfs)) != filesize) {
		printf("Header file size sums doesn't match with the actual file size.\n");
		return 0;
	}

	bodysize = filesize - TCL_HEADER_SIZE;

	// Read file body
	filebody = (char*)malloc(bodysize);
	if (filebody == NULL) {
		printf("Can't allocate memory.\n");
		return 0;
	}

	memset((char*)filebody, 0x00, bodysize);
	bytesread = fread(filebody, 1, bodysize, tclfile);

	if (bytesread != bodysize) {
		printf("Fail reading file body.\n");
		free(filebody);
		return 0;
	}

	// Read CRC32 and convert endianness 
	uint32_t found_tclinux_checksum = ntohl(header.crc32);

	// Calculate CRC32 from what we have read from the file
	crc32 = crc32buf(filebody, bodysize);

	if (found_tclinux_checksum != crc32) {
		printf("CRC32 on the header does not match with the calculated one.\n");
		free(filebody);
		return 0;
	}

	if (headerout != NULL) {
		memcpy(headerout, &header, sizeof(struct tcl_header));
	}

	free(filebody);

	return 1;
}

int main(int argc, const char *argv[])
{
	FILE *fp;
	runmode mode = HELP;
	const char *openfile = NULL;
	const char *kernelfile = NULL;
	const char *rootfsfile = NULL;
	const char *version = NULL;
	const char *versioncustom = NULL;
	const char *devicemodel = NULL;
	uint32_t magic = 0;
	uint32_t kerneldecompressaddr = 0;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
			mode = HELP;
			break;
		}
		else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--test") == 0) {
			mode = TEST;
			openfile = argv[++i];
			break;
		}
		else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--extract") == 0) {
			mode = EXTRACT;
			openfile = argv[++i];
			kernelfile = argv[++i];
			rootfsfile = argv[++i];
			continue;
		}
		else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--create") == 0) {
			mode = CREATE;
			openfile = argv[++i];
			continue;
		}
		else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--kernel") == 0) {
			kernelfile = argv[++i];
			continue;
		}
		else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--rootfs") == 0) {
			rootfsfile = argv[++i];
			continue;
		}
		else if (strcmp(argv[i], "-da") == 0 || strcmp(argv[i], "--decompress-addr") == 0) {
			kerneldecompressaddr = (uint32_t)strtoll(argv[++i], NULL, 16);
			continue;
		}
		else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
			version = argv[++i];

			if (strlen(version) > 32) {
				printf("Version string can't be longer than 32 characters.");
				return 2;
			}

			continue;
		}
		else if (strcmp(argv[i], "-vc") == 0 || strcmp(argv[i], "--version-custom") == 0) {
			versioncustom = argv[++i];

			if (strlen(versioncustom) > 32) {
				printf("Version custom string can't be longer than 32 characters.");
				return 2;
			}

			continue;
		}
		else if (strcmp(argv[i], "-dm") == 0 || strcmp(argv[i], "--device-model") == 0) {
			devicemodel = argv[++i];

			if (strlen(devicemodel) > 32) {
				printf("Device model string can't be longer than 32 characters.");
				return 2;
			}

			continue;
		}
		else if (strcmp(argv[i], "-ma") == 0 || strcmp(argv[i], "--magic") == 0) {
			magic = (uint32_t)strtoll(argv[++i], NULL, 16);
			continue;
		}
	}

	if (mode == HELP) {
		printf("Usage: %s <args>\n"
			"-t (--test)     Test file integrity (-t input.bin)\n"
			"-e (--extract)  Extract kernel and rootfs (-e input.bin kernel.bin rootfs.bin)\n"
			"-c (--create)   Create tclinux image (-c output.bin -k kernel.bin -r rootfs.bin)\n"
			"Options for create:\n"
			"-da (--decompress-addr)    RAM address (hex, 32-bit) for kernel to place on\n"
			"-v  (--version)            Version string for firmware (32 chars)\n"
			"-vc (--version-custom)     Version (customized) string for firmware (32 chars)\n"
			"-dm (--device-model)       Device model (32 chars)\n"
			"-ma (--magic)              Header magic (hex, 32 bit)\n", argv[0]);
		return 2;
	}

	if (mode == TEST) {
		struct tcl_header header;

		fp = fopen(openfile, "rb");

		if (fp == NULL) {
			perror("Fail opening input file:");
			return 1;
		}

		int retcode = 0;
		if (checktcl(fp, &header) == 1) {
			printf("All checks OK!\n");
			printf("header.magic: 0x%08X\n", ntohl(header.magic));
			printf("header.version: %s\n", header.version);
			printf("header.versioncustom: %s\n", header.versioncustom);
			printf("header.devicemodel: %s\n", header.devicemodel);
			printf("header.crc32: 0x%08X\n", ntohl(header.crc32));
			printf("header.decompressaddr: 0x%08X\n", ntohl(header.decompressaddr));
			printf("header.lenfile: %d\n", ntohl(header.lenfile));
			printf("header.lenheader: %d\n", ntohl(header.lenheader));
			printf("header.lenkernel: %d\n", ntohl(header.lenkernel));
			printf("header.lenrootfs: %d\n", ntohl(header.lenrootfs));
		} else {
			printf("Some checks FAIL!\n");
			retcode = 1;
		}

		fclose(fp);
		return retcode;
	}

	if (mode == EXTRACT) {
		size_t filesize = 0;
		size_t bodysize = 0;
		size_t bytesread = 0;
		size_t byteswritten = 0;
		char *filebody = NULL;
		struct tcl_header header;

		fp = fopen(openfile, "rb");

		if (fp == NULL) {
			printf("Fail opening file.\n");
			return 1;
		}

		if (checktcl(fp, &header) == 0) {
			return 1;
		}

		// Get file size
		fseek(fp, 0L, SEEK_END);
		filesize = ftell(fp);
		rewind(fp);

		// Calculate body size
		fseek(fp, TCL_HEADER_SIZE, 0);
		bodysize = filesize - TCL_HEADER_SIZE;

		// Read body (we already have header by the checktcl call above)
		filebody = (char*)malloc(bodysize);
		if (filebody == NULL) {
			printf("Can't allocate memory.\n");
			return 0;
		}

		memset((char*)filebody, 0x00, bodysize);
		bytesread = fread(filebody, 1, bodysize, fp);

		if (bytesread != bodysize) {
			printf("Fail reading file body.\n");
			free(filebody);
			return 1;
		}

		FILE *kernelp = NULL;
		FILE *rootfsp = NULL;

		// Try opening kernel file
		kernelp = fopen(kernelfile, "wb");
		if (kernelp == NULL) {
			perror("Fail opening kernel file for writting:");
			free(filebody);
			return 1;
		}

		// Try opening rootfs file
		rootfsp = fopen(rootfsfile, "wb");
		if (rootfsp == NULL) {
			perror("Fail opening rootfs file for writting:");
			free(filebody);
			fclose(kernelp);
			return 1;
		}

		// Try writting kernel file
		byteswritten = fwrite(filebody, 1, ntohl(header.lenkernel), kernelp);
		if (byteswritten != ntohl(header.lenkernel)) {
			printf("Fail writting kernel file '%s'.\n", kernelfile);
			free(filebody);
			fclose(kernelp);
			fclose(rootfsp);
			return 1;
		}

		// Try writting rootfs file
		byteswritten = fwrite(filebody + ntohl(header.lenkernel), 1, ntohl(header.lenrootfs), rootfsp);
		if (byteswritten != ntohl(header.lenrootfs)) {
			free(filebody);
			fclose(kernelp);
			fclose(rootfsp);
			printf("Fail writting rootfs file '%s'.\n", kernelfile);
			return 1;
		}

		// Cleanup
		free(filebody);
		fclose(fp);
		fclose(kernelp);
		fclose(rootfsp);

		printf("File '%s' extracted sucessfully.\n", openfile);
		return 0;
	}

	if (mode == CREATE) {
		uint32_t crc;
		int kernelsize = 0;
		int rootfssize = 0;
		size_t bytesread = 0;
		char *filebody = NULL;
		char *kerneldata = NULL;
		char *rootfsdata = NULL;
		struct tcl_header header;

		FILE *kernelp = NULL;
		FILE *rootfsp = NULL;
		FILE *outfile = NULL;

		if (kernelfile == NULL) {
			printf("kernel file parameter not specified!");
			return 1;
		}

		if (rootfsfile == NULL) {
			printf("kernel file parameter not specified!");
			return 1;
		}

		// Try opening kernel file
		kernelp = fopen(kernelfile, "rb");
		if (kernelp == NULL) {
			perror("Fail opening kernel file for reading:");
			return 1;
		}

		// Try opening rootfs file
		rootfsp = fopen(rootfsfile, "rb");
		if (rootfsp == NULL) {
			perror("Fail opening rootfs file for reading:");
			fclose(kernelp);
			return 1;
		}

		// Find kernel file size
		fseek(kernelp, 0L, SEEK_END);
		kernelsize = ftell(kernelp);
		rewind(kernelp);

		// Find rootfs file size
		fseek(rootfsp, 0L, SEEK_END);
		rootfssize = ftell(rootfsp);
		rewind(rootfsp);

		// Alloc buffers
		kerneldata = (char*)malloc(kernelsize);
		if (kerneldata == NULL) {
			printf("Can't allocate memory.\n");
			return 0;
		}

		rootfsdata = (char*)malloc(rootfssize);
		if (rootfsdata == NULL) {
			printf("Can't allocate memory.\n");
			free(kerneldata);
			return 0;
		}

		filebody = (char*)malloc(kernelsize + rootfssize);
		if (filebody == NULL) {
			printf("Can't allocate memory.\n");
			free(kerneldata);
			free(rootfsdata);
			return 0;
		}

		// Try reading kernel file
		bytesread = fread(kerneldata, 1, kernelsize, kernelp);
		if (bytesread != kernelsize) {
			printf("Fail reading kernel file.\n");
			fclose(kernelp);
			fclose(rootfsp);
			free(filebody);
			free(kerneldata);
			free(rootfsdata);
			return 1;
		}

		// Try reading rootfs file
		bytesread = fread(rootfsdata, 1, rootfssize, rootfsp);
		if (bytesread != rootfssize) {
			printf("Fail reading rootfs file.\n");
			fclose(kernelp);
			fclose(rootfsp);
			free(filebody);
			free(kerneldata);
			free(rootfsdata);
			return 1;
		}

		memcpy(filebody, kerneldata, kernelsize);
		memcpy(filebody+kernelsize, rootfsdata, rootfssize);

		// Init the header
		memset(&header, 0x00, TCL_HEADER_SIZE);

		if (magic) {
		    header.magic = htonl(magic);
		} else {
		    header.magic = htonl(TCL_MAGIC);
		}

		// Calculate CRC32 of the file
		crc = crc32buf(filebody, kernelsize + rootfssize);
		header.crc32 = htonl(crc);

		// Copy strings to header
		memcpy(header.version, version, strlen(version));
		memcpy(header.devicemodel, devicemodel, strlen(devicemodel));

		// Version custom can be empty
		if(versioncustom != NULL)
			memcpy(header.versioncustom, versioncustom, strlen(versioncustom));

		// Fill lenght fields
		header.lenkernel = htonl(kernelsize);
		header.lenrootfs = htonl(rootfssize);
		header.lenheader = htonl(TCL_HEADER_SIZE);
		header.lenfile = htonl(TCL_HEADER_SIZE + kernelsize + rootfssize);

		header.decompressaddr = htonl(kerneldecompressaddr);

		outfile = fopen(openfile, "wb");

		// Write the final data to the file
		fwrite(&header, 1, TCL_HEADER_SIZE, outfile);
		fwrite(kerneldata, 1, kernelsize, outfile);
		fwrite(rootfsdata, 1, rootfssize, outfile);
		
		// Cleanup
		free(kerneldata);
		free(rootfsdata);
		free(filebody);
		fclose(outfile);
		fclose(kernelp);
		fclose(rootfsp);

		printf("File '%s' built succesfully.\n", openfile);
		return 0;
	}
}
