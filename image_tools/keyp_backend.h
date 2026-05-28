/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2026 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2026 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Internal keypair backend vtable — included by crypto_ops.c and key_*.c only.
 */
#ifndef _KEYP_BACKEND_H
#define _KEYP_BACKEND_H

#include <stdint.h>
#include <stddef.h>
#include <crypto.h>

#define KEYP_OPEN_FORCE_NEW	(1 << 0)

struct keyp_ops {
	void		*ctx;		/* backend private state */
	crypto_algo_t	 algo;		/* set by backend constructor */
	int             (*keyp_open)(struct keyp_ops *ops, int flags);
	const uint8_t  *(*keyp_get_pubkey)(struct keyp_ops *ops);
	int             (*keyp_sign)(struct keyp_ops *ops,
			  const uint8_t *msg, size_t msglen, uint8_t *sig_out);
	void (*keyp_close)(struct keyp_ops *ops);
};

#endif /* _KEYP_BACKEND_H */
