/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2026 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2026 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * File-backed keypair backend.
 *
 * Key material lifecycle:
 *   keyp_open  — decrypt PKCS#8 PEM → extract 32-byte scalar →
 *                copy into memfd_secret page → EVP_PKEY_free → guard page
 *   keyp_sign  — unguard → EVP_PKEY_new_raw_private_key (transient) →
 *                re-guard → EVP_DigestSign → EVP_PKEY_free
 *   keyp_close — unguard → explicit_bzero → munmap
 */
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <utils.h>
#include "keyp_backend.h"
#include "key_file.h"

#ifndef SYS_memfd_secret
#define SYS_memfd_secret 447
#endif

#define PASS_MAX_LEN	256
#define ED25519_KEY_LEN	32


/*********************\
* Secret memory (skey)*
\*********************/

struct skey_t {
	uint8_t priv[ED25519_KEY_LEN];
};

static size_t
skey_pgsz(void)
{
	long pgsz = sysconf(_SC_PAGESIZE);

	if (pgsz <= 0)
		pgsz = 4096;
	return ((sizeof(struct skey_t) + (size_t)pgsz - 1) &
		~((size_t)pgsz - 1));
}

static struct skey_t *
skey_alloc(void)
{
	size_t sz = skey_pgsz();
	int fd = (int)syscall(SYS_memfd_secret, 0UL);
	void *p = MAP_FAILED;

	if (fd < 0) {
		ERR("memfd_secret: %s\n", strerror(errno));
		return NULL;
	}
	if (ftruncate(fd, (off_t)sz) < 0) {
		ERR("ftruncate memfd_secret: %s\n", strerror(errno));
		close(fd);
		return NULL;
	}
	p = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (p == MAP_FAILED) {
		ERR("mmap memfd_secret: %s\n", strerror(errno));
		return NULL;
	}
	memset(p, 0, sz);
	if (mprotect(p, sz, PROT_NONE) < 0) {
		ERR("mprotect PROT_NONE: %s\n", strerror(errno));
		munmap(p, sz);
		return NULL;
	}
	return (struct skey_t *)p;
}

/* Returns 0 on success, -1 if mprotect fails (key material exposed). */
static int
skey_guard(struct skey_t *sk)
{
	if (!sk)
		return 0;
	if (mprotect(sk, skey_pgsz(), PROT_NONE) < 0) {
		ERR("skey_guard: mprotect failed: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/* Returns 0 on success, -1 if mprotect fails (access would SIGSEGV). */
static int
skey_unguard(struct skey_t *sk)
{
	if (!sk)
		return 0;
	if (mprotect(sk, skey_pgsz(), PROT_READ | PROT_WRITE) < 0) {
		ERR("skey_unguard: mprotect failed: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static void
skey_free(struct skey_t *sk)
{
	size_t sz = skey_pgsz();

	if (!sk)
		return;
	(void)mprotect(sk, sz, PROT_READ | PROT_WRITE); /* best-effort */
	explicit_bzero(sk, sz);
	munmap(sk, sz);
}


/*********************\
* Passphrase via pinentry *
\*********************/

static const char * const pinentry_variants[] = {
	"pinentry-gnome3",
	"pinentry-gtk-2",
	"pinentry-qt",
	"pinentry-curses",
	"pinentry-tty",
	"pinentry",
	NULL
};

/*
 * Speak the Assuan protocol to a pinentry child.
 * Returns 0 on success, -1 if no pinentry found or user cancelled.
 */
static int
pass_read(const char *desc, const char *prompt, int confirm,
	  char *buf, size_t bufsz)
{
	int pin_to[2]   = { -1, -1 };
	int pin_from[2] = { -1, -1 };
	char line[512];
	FILE *to = NULL, *from = NULL;
	pid_t pid = -1;
	int i = 0, ret = -1;

	memset(buf, 0, bufsz);

	if (pipe2(pin_to, O_CLOEXEC) < 0 || pipe2(pin_from, O_CLOEXEC) < 0)
		goto out;

	pid = fork();
	if (pid < 0)
		goto out;

	if (pid == 0) {
		close(pin_to[1]);
		close(pin_from[0]);
		dup2(pin_to[0],   STDIN_FILENO);
		dup2(pin_from[1], STDOUT_FILENO);
		close(pin_to[0]);
		close(pin_from[1]);
		for (i = 0; pinentry_variants[i]; i++)
			execlp(pinentry_variants[i], pinentry_variants[i], NULL);
		_exit(127);
	}

	close(pin_to[0]);   pin_to[0]   = -1;
	close(pin_from[1]); pin_from[1] = -1;
	to   = fdopen(pin_to[1],   "w");
	from = fdopen(pin_from[0], "r");
	if (!to || !from)
		goto out;

	if (!fgets(line, sizeof(line), from) || strncmp(line, "OK", 2) != 0)
		goto out;

	fprintf(to, "SETDESC %s\n", desc);
	fflush(to);
	if (!fgets(line, sizeof(line), from) || strncmp(line, "OK", 2) != 0)
		goto out;

	fprintf(to, "SETPROMPT %s\n", prompt);
	fflush(to);
	if (!fgets(line, sizeof(line), from) || strncmp(line, "OK", 2) != 0)
		goto out;

	if (confirm) {
		fprintf(to, "SETREPEAT Confirm passphrase\n");
		fflush(to);
		if (!fgets(line, sizeof(line), from) ||
		    strncmp(line, "OK", 2) != 0)
			goto out;
	}

	fprintf(to, "GETPIN\n");
	fflush(to);

	/* Skip S (status/informational) lines — e.g. "S PIN_REPEATED" */
	do {
		if (!fgets(line, sizeof(line), from)) {
			ERR("pinentry: lost connection after GETPIN\n");
			goto out;
		}
	} while (strncmp(line, "S ", 2) == 0);

	if (strncmp(line, "D ", 2) == 0) {
		size_t len = strlen(line + 2);

		if (len > 0 && line[2 + len - 1] == '\n') {
			line[2 + len - 1] = '\0';
			len--;
		}
		if (len >= bufsz)
			len = bufsz - 1;
		memcpy(buf, line + 2, len);
		buf[len] = '\0';
		explicit_bzero(line, sizeof(line));
		if (!fgets(line, sizeof(line), from)) { /* consume trailing OK */ }
		ret = 0;
	} else if (strncmp(line, "ERR ", 4) == 0) {
		ERR("pinentry: %s", line + 4);
	} else {
		ERR("pinentry: unexpected GETPIN response: %s", line);
	}

	fprintf(to, "BYE\n");
	fflush(to);

out:
	explicit_bzero(line, sizeof(line));
	if (to)   { fclose(to);   pin_to[1]   = -1; }
	if (from) { fclose(from); pin_from[0] = -1; }
	if (pin_to[0]   >= 0) close(pin_to[0]);
	if (pin_to[1]   >= 0) close(pin_to[1]);
	if (pin_from[0] >= 0) close(pin_from[0]);
	if (pin_from[1] >= 0) close(pin_from[1]);
	if (pid > 0)
		waitpid(pid, NULL, 0);
	return ret;
}

/*
 * PEM passphrase callback.
 *
 * The OpenSSL-supplied `buf` cannot be cleared by us here — PEM_read_PrivateKey
 * needs to read it after we return.  OpenSSL ≥ 1.1 cleanses this buffer
 * itself once decryption is done.  Our copy of the passphrase (`userdata`,
 * i.e. the `pass` array in kf_open) is explicit_bzero'd in kf_open's
 * cleanup, so the only window in which the passphrase is in plaintext memory
 * is bounded by PEM_read_PrivateKey's runtime.
 *
 * SETDESC / SETPROMPT in pass_read assume hardcoded literal arguments
 * (no user-controlled strings); newline injection is not a concern as long
 * as that holds.
 */
static int
pem_pass_cb(char *buf, int size, int rwflag, void *userdata)
{
	const char *pass = (const char *)userdata;
	int len = (int)strlen(pass);

	(void)rwflag;
	if (len > size)
		len = size;
	memcpy(buf, pass, (size_t)len);
	return len;
}


/**********************\
* Backend private state *
\**********************/

struct kf_ctx {
	struct skey_t	*skey;
	uint8_t		 pub[ED25519_KEY_LEN];
	size_t		 pub_len;
};


/***********************\
* Vtable implementations *
\***********************/

static int
kf_open(struct keyp_ops *ops, int flags)
{
	struct kf_ctx *kf = NULL;
	EVP_PKEY_CTX  *pctx = NULL;
	EVP_PKEY      *evp_key = NULL;
	FILE          *fp = NULL;
	struct stat    st;
	const char    *path = (const char *)ops->ctx;
	char           pass[PASS_MAX_LEN];
	char           pub_path[PATH_MAX];
	uint8_t        raw_priv[ED25519_KEY_LEN];
	uint8_t        raw_pub[ED25519_KEY_LEN];
	size_t         raw_priv_len = sizeof(raw_priv);
	size_t         raw_pub_len  = sizeof(raw_pub);
	int            generate = 0, ret = -1;

	/* Null ctx immediately so kf_close is safe if we fail before
	 * the ops->ctx = kf assignment at the end. */
	ops->ctx = NULL;

	kf = malloc(sizeof(struct kf_ctx));
	if (!kf)
		return -1;
	memset(kf, 0, sizeof(struct kf_ctx));

	kf->skey = skey_alloc();
	if (!kf->skey)
		goto cleanup;

	generate = (flags & KEYP_OPEN_FORCE_NEW);
	if (!generate) {
		if (stat(path, &st) == 0) {
			generate = 0;
		} else if (errno == ENOENT) {
			generate = 1;
		} else {
			ERR("stat %s: %s\n", path, strerror(errno));
			goto cleanup;
		}
	}

	if (generate) {
		if (pass_read("Generate new Ed25519 signing key",
			      "New passphrase", 1,
			      pass, sizeof(pass)) < 0) {
			ERR("Failed to read passphrase\n");
			goto cleanup;
		}

		pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
		if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 ||
		    EVP_PKEY_keygen(pctx, &evp_key) <= 0) {
			ERR("Key generation failed\n");
			goto cleanup;
		}
		EVP_PKEY_CTX_free(pctx);
		pctx = NULL;

		if (EVP_PKEY_get_raw_private_key(evp_key, raw_priv,
						 &raw_priv_len) != 1 ||
		    EVP_PKEY_get_raw_public_key(evp_key, raw_pub,
					       &raw_pub_len) != 1) {
			ERR("Failed to extract raw key material\n");
			goto cleanup;
		}

		/* Write encrypted PKCS#8 PEM, mode 0600 */
		{
			int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

			if (fd < 0) {
				ERR("open %s: %s\n", path, strerror(errno));
				goto cleanup;
			}
			fp = fdopen(fd, "w");
			if (!fp) {
				ERR("fdopen %s: %s\n", path, strerror(errno));
				close(fd);
				goto cleanup;
			}
			if (PEM_write_PrivateKey(fp, evp_key,
						 EVP_aes_256_cbc(),
						 (const unsigned char *)pass,
						 (int)strlen(pass),
						 NULL, NULL) != 1) {
				ERR("Failed to write encrypted private key\n");
				fclose(fp);
				fp = NULL;
				goto cleanup;
			}
			fclose(fp);
			fp = NULL;
		}

		snprintf(pub_path, sizeof(pub_path), "%.*s.pub",
			 (int)(sizeof(pub_path) - 5), path);
		fp = fopen(pub_path, "wb");
		if (!fp) {
			WRN("Could not write public key to %s: %s\n",
			    pub_path, strerror(errno));
		} else {
			if (fwrite(raw_pub, 1, raw_pub_len, fp) != raw_pub_len)
				WRN("Short write to %s\n", pub_path);
			fclose(fp);
			fp = NULL;
		}

		INF("Generated Ed25519 key pair:\n");
		INF("  Private : %s\n", path);
		INF("  Public  : %s.pub\n  (", path);
		for (size_t i = 0; i < raw_pub_len; i++)
			INF("%02x", raw_pub[i]);
		INF(")\n");

	} else {
		if (pass_read("Unlock Ed25519 signing key",
			      "Passphrase", 0,
			      pass, sizeof(pass)) < 0) {
			ERR("Failed to read passphrase\n");
			goto cleanup;
		}

		fp = fopen(path, "r");
		if (!fp) {
			ERR("fopen %s: %s\n", path, strerror(errno));
			goto cleanup;
		}
		evp_key = PEM_read_PrivateKey(fp, NULL, pem_pass_cb, pass);
		fclose(fp);
		fp = NULL;

		if (!evp_key) {
			ERR("Failed to load private key from %s"
			    " (wrong passphrase?)\n", path);
			goto cleanup;
		}

		if (EVP_PKEY_get_raw_private_key(evp_key, raw_priv,
						 &raw_priv_len) != 1 ||
		    EVP_PKEY_get_raw_public_key(evp_key, raw_pub,
					       &raw_pub_len) != 1) {
			ERR("Failed to extract raw key material\n");
			goto cleanup;
		}
	}

	/* Scalar → guarded skey; public key → plain kf_ctx */
	if (skey_unguard(kf->skey) < 0)
		goto cleanup;
	memcpy(kf->skey->priv, raw_priv, raw_priv_len);
	if (skey_guard(kf->skey) < 0)
		goto cleanup;

	memcpy(kf->pub, raw_pub, raw_pub_len);
	kf->pub_len = raw_pub_len;

	ops->ctx = kf;
	ret = 0;

cleanup:
	explicit_bzero(raw_priv, sizeof(raw_priv));
	explicit_bzero(pass, sizeof(pass));
	if (evp_key)
		EVP_PKEY_free(evp_key);
	if (pctx)
		EVP_PKEY_CTX_free(pctx);
	if (fp)
		fclose(fp);
	if (ret < 0) {
		skey_free(kf ? kf->skey : NULL);
		free(kf);
	}
	return ret;
}

static const uint8_t *
kf_get_pubkey(struct keyp_ops *ops)
{
	const struct kf_ctx *kf = (const struct kf_ctx *)ops->ctx;

	return (kf && kf->pub_len > 0) ? kf->pub : NULL;
}

static int
kf_sign(struct keyp_ops *ops,
	const uint8_t *msg, size_t msglen, uint8_t *sig_out)
{
	struct kf_ctx *kf = (struct kf_ctx *)ops->ctx;
	EVP_PKEY      *evp_key = NULL;
	EVP_MD_CTX    *mdctx = NULL;
	size_t         siglen = 64;
	int            ret = -1;

	if (!kf || !kf->skey)
		return -1;

	/* Unguard only for the memcpy inside EVP_PKEY_new_raw_private_key */
	if (skey_unguard(kf->skey) < 0)
		return -1;
	evp_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
					       kf->skey->priv, ED25519_KEY_LEN);
	if (skey_guard(kf->skey) < 0) {
		/* Cannot re-protect key page — zero it and abort */
		explicit_bzero(kf->skey, skey_pgsz());
		EVP_PKEY_free(evp_key);
		return -1;
	}

	if (!evp_key) {
		ERR("EVP_PKEY_new_raw_private_key failed\n");
		return -1;
	}

	mdctx = EVP_MD_CTX_new();
	if (!mdctx)
		goto out;

	if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, evp_key) == 1 &&
	    EVP_DigestSign(mdctx, sig_out, &siglen, msg, msglen) == 1)
		ret = 0;
	else
		ERR("Ed25519 signing failed\n");

	EVP_MD_CTX_free(mdctx);
out:
	EVP_PKEY_free(evp_key);
	return ret;
}

static void
kf_close(struct keyp_ops *ops)
{
	struct kf_ctx *kf = (struct kf_ctx *)ops->ctx;

	if (!kf)
		return;
	skey_free(kf->skey);
	explicit_bzero(kf->pub, sizeof(kf->pub));
	free(kf);
	ops->ctx = NULL;
}


/********************\
* Backend constructor *
\********************/

struct keyp_ops *
keyp_file_backend(const char *path)
{
	struct keyp_ops *ops = NULL;

	ops = malloc(sizeof(struct keyp_ops));
	if (!ops)
		return NULL;
	memset(ops, 0, sizeof(struct keyp_ops));

	/*
	 * Stash path in ctx; kf_open replaces it with the allocated
	 * kf_ctx once the key is loaded or generated.
	 */
	ops->ctx             = (void *)path;
	ops->algo            = CRYPTO_ALGO_ED25519;
	ops->keyp_open       = kf_open;
	ops->keyp_get_pubkey = kf_get_pubkey;
	ops->keyp_sign       = kf_sign;
	ops->keyp_close      = kf_close;
	return ops;
}
