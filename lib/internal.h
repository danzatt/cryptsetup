#ifndef INTERNAL_H
#define INTERNAL_H

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>

#define SECTOR_SHIFT		9
#define SECTOR_SIZE		(1 << SECTOR_SHIFT)
#define DEFAULT_ALIGNMENT	4096

/* private struct crypt_options flags */

#define	CRYPT_FLAG_FREE_DEVICE	(1 << 24)
#define	CRYPT_FLAG_FREE_CIPHER	(1 << 25)

#define CRYPT_FLAG_PRIVATE_MASK ((unsigned int)-1 << 24)

struct hash_type {
	char		*name;
	void		*private;
	int		(*fn)(void *data, int size, char *key,
			      int sizep, const char *passphrase);
};

struct hash_backend {
	const char		*name;
	struct hash_type *	(*get_hashes)(void);
	void			(*free_hashes)(struct hash_type *hashes);
};

struct crypt_device;

void set_error_va(const char *fmt, va_list va);
void set_error(const char *fmt, ...);
const char *get_error(void);
void *safe_alloc(size_t size);
void safe_free(void *data);
void *safe_realloc(void *data, size_t size);
char *safe_strdup(const char *s);

struct hash_backend *get_hash_backend(const char *name);
void put_hash_backend(struct hash_backend *backend);
int hash(const char *backend_name, const char *hash_name,
         char *result, size_t size,
         const char *passphrase, size_t sizep);

void hexprint(char *d, int n);

/* Device mapper backend */
const char *dm_get_dir(void);
int dm_init(struct crypt_device *context, int check_kernel);
void dm_exit(void);
int dm_remove_device(const char *name, int force, uint64_t size);
int dm_status_device(const char *name);
int dm_query_device(const char *name,
		    char **device,
		    uint64_t *size,
		    uint64_t *skip,
		    uint64_t *offset,
		    char **cipher,
		    int *key_size,
		    char **key,
		    int *read_only);
int dm_create_device(const char *name, const char *device, const char *cipher, const char *uuid,
		     uint64_t size, uint64_t skip, uint64_t offset,
		     size_t key_size, const char *key,
		     int read_only, int reload);

int sector_size_for_device(const char *device);
ssize_t write_blockwise(int fd, const void *buf, size_t count);
ssize_t read_blockwise(int fd, void *_buf, size_t count);
ssize_t write_lseek_blockwise(int fd, const char *buf, size_t count, off_t offset);


int get_key(char *prompt, char **key, unsigned int *passLen, int key_size,
            const char *key_file, int passphrase_fd, int timeout, int how2verify);

#endif /* INTERNAL_H */
