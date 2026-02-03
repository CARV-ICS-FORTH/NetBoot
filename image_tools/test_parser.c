/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2026 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2026 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * Test harness for image parser
 * Feeds boot.img through imgp_tftp_handler in chunks
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <img.h>

/* From units/self.c */
extern size_t test_get_partition_size(int part_id);

#define CHUNK_SIZE 512  /* Typical TFTP block size */

int main(int argc, char *argv[])
{
	const char *img_path = "../tftp-root/boot.img";

	if (argc > 1)
		img_path = argv[1];

	printf("=== Image Parser Test ===\n");
	printf("Input file: %s\n", img_path);
	printf("Chunk size: %d bytes\n\n", CHUNK_SIZE);

	/* Open input file */
	FILE *fp = fopen(img_path, "rb");
	if (!fp) {
		perror("fopen");
		return 1;
	}

	/* Get file size */
	fseek(fp, 0, SEEK_END);
	long file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	printf("File size: %ld bytes\n\n", file_size);

	/* Initialize parser state */
	ImgpState *imgp = imgp_init_state();
	if (!imgp) {
		fprintf(stderr, "Error: Failed to initialize parser state\n");
		fclose(fp);
		return 1;
	}

	/* Process file in chunks */
	uint8_t buffer[CHUNK_SIZE];
	size_t total_read = 0;
	size_t chunk_num = 0;
	int ret = 0;

	printf("Processing chunks:\n");
	while (!feof(fp)) {
		size_t bytes_read = fread(buffer, 1, CHUNK_SIZE, fp);
		if (bytes_read == 0)
			break;

		total_read += bytes_read;
		chunk_num++;

		printf("  Chunk %zu: %zu bytes (total: %zu/%ld)\n",
		       chunk_num, bytes_read, total_read, file_size);

		/* Feed to parser */
		ret = imgp_tftp_handler(imgp, buffer, bytes_read);
		if (ret < 0) {
			fprintf(stderr, "\nError: Parser returned %d (%s)\n",
			        ret, strerror(-ret));
			fclose(fp);
			imgp_clear_state();
			return 1;
		}
	}
	fclose(fp);
	ret = imgp_tftp_handler(imgp, NULL, 0);

	/* Clean up parser state */
	imgp_clear_state();

	printf("\n=== Parsing Complete ===\n");
	printf("Total chunks: %zu\n", chunk_num);
	printf("Total bytes: %zu\n", total_read);
	printf("Parser returned: %d bytes written\n", ret);

	/* Truncate files to actual sizes */
	size_t part0_size = test_get_partition_size(0);
	size_t part1_size = ret - part0_size;  /* total_bytes_out - part0_size */

	printf("\nTruncating output files:\n");
	printf("  /tmp/part0.bin: %zu bytes\n", part0_size);
	printf("  /tmp/part1.bin: %zu bytes\n", part1_size);

	if (part0_size > 0 && truncate("/tmp/part0.bin", part0_size) < 0) {
		perror("truncate part0");
		return 1;
	}

	if (part1_size > 0 && truncate("/tmp/part1.bin", part1_size) < 0) {
		perror("truncate part1");
		return 1;
	}

	printf("\nVerify with:\n");
	printf("  md5sum ../tftp-root/boot.bin /tmp/part0.bin\n");
	printf("  md5sum ../tftp-root/boot.dtb /tmp/part1.bin\n");

	return 0;
}
