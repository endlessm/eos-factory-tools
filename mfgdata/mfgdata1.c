#define _BSD_SOURCE
#include <glob.h>
#include <endian.h>
#include <stdio.h>
#include <getopt.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <glib.h>

#define DATA_BLOB_SIZE 4096

/* Buffer used for both read-in (parsing) and data write-out. */
static unsigned char *buf;

/* Current read or write offset into buf */
static unsigned int pos;

/* Our in-memory copy of the parsed data, or data to be written out */
static GHashTable *entries;

enum tag_data_type {
	TAG_TYPE_ASCII,
	TAG_TYPE_MAC_ADDRESS,
};

static const struct tag_info {
	const char *tag;
	const char *description;
	gboolean required;
	uint16_t required_length;
	enum tag_data_type type;
} tag_info[] = {
	{
		.tag = "PF",
		.description = "Endless Product Family",
		.required = TRUE,
		.required_length = 0,
		.type = TAG_TYPE_ASCII,
	}, {
		.tag = "PID",
		.description = "Endless Product ID",
		.required = TRUE,
		.required_length = 0,
		.type = TAG_TYPE_ASCII,
	}, {
		.tag = "SKU",
		.description = "SKU identifier",
		.required = TRUE,
		.required_length = 0,
		.type = TAG_TYPE_ASCII,
	}, {
		.tag = "SSN",
		.description = "System Serial Number",
		.required = TRUE,
		.required_length = 19,
		.type = TAG_TYPE_ASCII,
	}, {
		.tag = "BSN",
		.description = "Board Serial Number",
		.required = TRUE,
		.required_length = 24,
		.type = TAG_TYPE_ASCII,
	}, {
		.tag = "EMAC",
		.description = "Ethernet MAC address",
		.required = TRUE,
		.required_length = 6,
		.type = TAG_TYPE_MAC_ADDRESS,
	}, {
		.tag = "BMAC",
		.description = "Bluetooth MAC address",
		.required = FALSE,
		.required_length = 6,
		.type = TAG_TYPE_MAC_ADDRESS,
	},
};

static const struct tag_info *find_tag_info(const char *tag)
{
	int i;
	for (i = 0; i < G_N_ELEMENTS(tag_info); i++) {
		if (strcmp(tag_info[i].tag, tag) == 0)
			return &tag_info[i];
	}
	return NULL;
}

/* Open eMMC device and seek to location of manufacturing data */
static FILE *open_emmc(const char *mode)
{
	FILE *fd;
	glob_t globbuf;

	glob("/dev/mmcblk?boot0", 0, NULL, &globbuf);
	if (globbuf.gl_pathc < 1) {
		fprintf(stderr, "Failed to find eMMC device\n");
		return FALSE;
	}

	fd = fopen(globbuf.gl_pathv[0], mode);
	globfree(&globbuf);
	if (!fd) {
		fprintf(stderr, "Failed to open %s with mode %s\n", "mmc", mode);
		return NULL;
	}

	if (fseek(fd, -8192, SEEK_END) < 0) {
		perror("Failed eMMC seek\n");
		fclose(fd);
		return NULL;
	}

	return fd;
}

/* Write an in-memory entry into the raw data buffer */
static gboolean write_entry(const char *tag, uint16_t length,
							const unsigned char *data)
{
	int tag_len = strlen(tag);

	/* Check we can write this entry and have at least 1 byte free to write
	 * the EOF */
	if (pos + tag_len + 1 + 2 + length >= DATA_BLOB_SIZE - 1)
		return FALSE;

	strcpy((char *) buf + pos, tag);
	pos += strlen(tag) + 1;

	*((uint16_t *) (buf + pos)) = htole16(length);
	pos += 2;

	memcpy(buf + pos, data, length);
	pos += length;

	return TRUE;
}

/* Write the in-memory entries into the raw data buffer, then write to disk */
static gboolean write_to_disk(void)
{
	gboolean ret = TRUE;
	GHashTableIter iter;
	unsigned char mfgdata_value[] = { 0xdd, 0xcc };
	char *tag;
	GBytes *data;
	FILE *fd;

	memset(buf, 0, DATA_BLOB_SIZE);
	pos = 0;
	write_entry("MFGDATA", 2, mfgdata_value);

	g_hash_table_iter_init(&iter, entries);
	while (g_hash_table_iter_next(&iter, (void **) &tag, (void **) &data)) {
		gsize length;
		gconstpointer value = g_bytes_get_data(data, &length);
		if (!write_entry(tag, length, value)) {
			fprintf(stderr, "Error: too much data to write\n");
			return FALSE;
		}
	}
	buf[pos++] = 0;

	fd = open_emmc("w");
	if (!fd)
		return FALSE;

	if (fwrite(buf, DATA_BLOB_SIZE, 1, fd) != 1) {
		perror("Write failed");
		ret = FALSE;
	}

	fclose(fd);
	return ret;
}

/*
 * Parse a single entry from the raw data buffer.
 *
 * Returns:
 *  1 : parse OK
 *  0 : EOF
 * -1 : parse fail
 */
static int parse_entry(const char **tag, uint16_t *length,
					   unsigned char **value)
{
	size_t maxsize = DATA_BLOB_SIZE - pos;
	size_t tag_len = strnlen((char *) buf + pos, maxsize);
	if (tag_len == maxsize)
		return -1;

	if (tag_len == 0)
		return 0;

	*tag = (char *) buf + pos;
	pos += tag_len + 1;

	if (pos >= DATA_BLOB_SIZE - 2)
		return -1;

	*length = le16toh(*((uint16_t *) (buf + pos)));
	pos += 2;

	if (pos >= DATA_BLOB_SIZE - *length)
		return -1;

	*value = buf + pos;
	pos += *length;

	return 1;
}

/* Parse and check the first entry, which is a mandatory format identifier. */
static gboolean parse_header(void)
{
	const char *tag;
	uint16_t length;
	unsigned char *value;

	if (parse_entry(&tag, &length, &value) != 1)
		return FALSE;

	return length == 2 && strcmp(tag, "MFGDATA") == 0 &&
		   value[0] == 0xdd && value[1] == 0xcc;
}

/* Append an entry to the in-memory hash table.
 * If there is already an entry with this tag, its value is overwritten. */
static void append_entry(const char *tag, uint16_t length,
						 const unsigned char *value)
{
	g_hash_table_replace(entries, g_strdup(tag), g_bytes_new(value, length));
}

/* Read the data from disk into the raw data buffer. */
static gboolean read_data_blob(void)
{
	FILE *fd = open_emmc("r");
	gboolean ret = TRUE;

	if (!fd)
		return FALSE;

	if (fread(buf, DATA_BLOB_SIZE, 1, fd) != 1)
		ret = FALSE;

	fclose(fd);
	pos = 0;
	return ret;
}

/* Read data from disk, and parse it into the hash table. */
static gboolean parse(void)
{
	const char *tag;
	uint16_t length;
	unsigned char *value;
	int r;

	if (!read_data_blob())
		return FALSE;

	if (!parse_header()) {
		fprintf(stderr,
				"Data error: no header found (do you need to init first?)\n");
		return FALSE;
	}

	while ((r = parse_entry(&tag, &length, &value)) == 1) {
		if (g_hash_table_contains(entries, tag)) {
			fprintf(stderr, "Data error: duplicate tag %s\n", tag);
			return FALSE;
		}

		append_entry(tag, length, value);
	}

	if (r == -1) {
		fprintf(stderr, "Data error: parse failure at %d\n", pos);
		g_hash_table_remove_all(entries);
		return FALSE;
	}

	return TRUE;
}

/* User action: Initialize the on-disk data block, being careful not to
 * accidently erase any existing data. */
static int do_init(int argc, char *argv[])
{
	read_data_blob();
	if (parse_header()) {
		if (argc == 0 || (argc > 0 && strcmp(argv[0], "--force"))) {
			fprintf(stderr,
					"Data may already be present. Add the --force parameter if "
					"you wish to\nreinitialize, erasing all data.\n");
			fprintf(stderr, "No action taken.\n");
			return 1;
		}
	}

	if (!write_to_disk())
		return 1;

	printf("Initialized empty manufacturing data block.\n");
	return 0;
}

static gboolean parse_mac_address(const char *str, unsigned char *out)
{
	unsigned int values[6];
	char dummy;
	int i;
	int r;

	r = sscanf(str, "%x:%x:%x:%x:%x:%x%c",
			   &values[0], &values[1], &values[2],
			   &values[3], &values[4], &values[5], &dummy);
	if (r != 6)
		return FALSE;

	for (i = 0; i < 6; i++) {
		if (values[i] >= 256)
			return FALSE;

		out[i] = (unsigned char) values[i];
	}

	return TRUE;
}

/* Parse an entry from the command line and add it to the hash table. */
static gboolean add_entry(const char *tag, const char *value)
{
	const struct tag_info *info = find_tag_info(tag);
	unsigned char parsed_mac[6];

	if (!info) {
		fprintf(stderr, "Unrecognised tag: %s\n", tag);
		return FALSE;
	}

	switch (info->type) {
	case TAG_TYPE_ASCII:
		if (strlen(value) == 0) {
			fprintf(stderr, "Tag %s has empty data.\n", tag);
			return FALSE;
		}

		append_entry(tag, strlen(value), (const unsigned char *) value);
		break;

	case TAG_TYPE_MAC_ADDRESS:
		if (!parse_mac_address(value, parsed_mac)) {
			fprintf(stderr, "Failed to parse MAC address: %s\n", value);
			return FALSE;
		}

		append_entry(tag, 6, parsed_mac);
		break;
	}

	return TRUE;
}

/* User action: write a number of entries */
static int do_write(int argc, char *argv[])
{
	int i;

	if (argc == 0 || argc % 2 != 0) {
		fprintf(stderr, "write requires an even number of (tag, value) "
				"parameter pairs\n");
		return 1;
	}

	if (!parse())
		return 1;

	for (i = 0; i < argc; i += 2)
		if (!add_entry(argv[i], argv[i + 1]))
			return 1;

	write_to_disk();

	return 0;
}

/* Print the value of an entry in human-readable form. It is checked
 * for validity and conformance at the same time. */
static gboolean print_and_check_entry(const char *tag, GBytes *data)
{
	gsize length;
	unsigned char *value = (unsigned char *) g_bytes_get_data(data, &length);
	const struct tag_info *info = find_tag_info(tag);

	printf("%s ", tag);

	if (!info) {
		printf("(unrecognised)\n");
		return FALSE;
	}

	if (length == 0) {
		printf("(invalid, empty data)\n");
		return FALSE;
	}

	printf("(%s): ", info->description);
	switch (info->type) {
	case TAG_TYPE_ASCII:
		printf("%.*s", (int) length, (char *) value);
		break;
	case TAG_TYPE_MAC_ADDRESS:
		if (length == 6)
			printf("%02X:%02X:%02X:%02X:%02X:%02X",
				   value[0], value[1], value[2], value[3], value[4], value[5]);
		break;
	}

	if (info->required_length > 0 && length != info->required_length) {
		printf(" (bad length, expected %d)\n", info->required_length);
		return FALSE;
	}

	printf("\n");
	return TRUE;
}

/* User action: print all entries and check the validity of the overall
 * data. */
static int do_check(void)
{
	GHashTableIter iter;
	const char *tag;
	GBytes *data;
	int i;
	gboolean ret = 0;

	if (!parse())
		return 1;

	printf("%d entries found.\n", g_hash_table_size(entries));

	/* Print and dump all existing entries */
	g_hash_table_iter_init(&iter, entries);
	while (g_hash_table_iter_next(&iter, (void **) &tag, (void **) &data))
		if (!print_and_check_entry(tag, data))
			ret = 1;

	/* Check that all required entries are present */
	for (i = 0; i < G_N_ELEMENTS(tag_info); i++) {
		if (!tag_info[i].required)
			continue;

		tag = tag_info[i].tag;
		if (!g_hash_table_contains(entries, tag)) {
			printf("Error: required tag '%s' not present\n", tag);
			ret = 1;
		}
	}

	return ret;
}

static void usage(const char *app)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, " %s init [--force]\n", app);
	fprintf(stderr, " %s write TAG VALUE\n", app);
	fprintf(stderr, " %s check\n", app);
}

int main(int argc, char *argv[])
{
	buf = g_malloc0(DATA_BLOB_SIZE);
	entries = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
									(GDestroyNotify) g_bytes_unref);

	if (argc < 2) {
		usage(argv[0]);
		exit(1);
	}

	if (strcmp(argv[1], "init") == 0)
		return do_init(argc - 2, argv + 2);
	else if (strcmp(argv[1], "write") == 0)
		return do_write(argc - 2, argv + 2);
	else if (strcmp(argv[1], "check") == 0)
		return do_check();

	fprintf(stderr, "Unrecognised action: %s\n", argv[1]);
	return 1;
}
