/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2026 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2026 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Internal header — included only by crypto_ops.c.
 */
#ifndef _KEY_FILE_H
#define _KEY_FILE_H

#include "keyp_backend.h"

/*
 * Allocate a keyp_ops backed by an AES-256-CBC encrypted PKCS#8 PEM
 * file at path.  The returned ops must be freed via cops_exit().
 */
struct keyp_ops *keyp_file_backend(const char *path);

#endif /* _KEY_FILE_H */
