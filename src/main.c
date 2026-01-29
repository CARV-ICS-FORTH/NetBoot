/*
 * SPDX-FileType: SOURCE
 *
 * SPDX-FileCopyrightText: 2023 Nick Kossifidis <mick@ics.forth.gr>
 * SPDX-FileCopyrightText: 2023 ICS/FORTH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <net.h>	/* For net_init/exit() */
#include <dhcp.h>	/* For dhcp_send_discover/release() */
#include <tftp.h>	/* For tftp_request_file() */
#include <stdlib.h>	/* For exit() */
#include <img.h>	/* For imgp_tftp_handler/unit_handler_self */
#include <errno.h>	/* For EINVAL */
#include <utils.h>	/* For console output */

int main(void) {
	#ifndef HOST_TEST
		#include <platform/interfaces/rng.h>
		/* Seed rand() before we begin, used for mac addresses
		 * and DHCP's xid etc later on. */
		srand(rng_get_seed());
	#endif

	/* Init network stack + ethernet driver */
	int ret = net_init();
	if (ret)
		goto done;

	/* Request IP and boot file from DHCP, loop until we get
	 * something. */
	do {
		ret = dhcp_send_discover(0,1);
	} while(ret);

	ImgpState* imgp = imgp_init_state();
	if (!imgp) {
		ERR("Couldn't init image parser's state\n");
		goto done;
	}

	ret = tftp_request_file(NULL, imgp_tftp_handler, imgp);
	if (ret < 0) {
		/* If DHCP-provided file failed (wrong format or no filename),
		 * reset parser state and try boot.img explicitly */
		ERR("First TFTP attempt failed with error %d, retrying with boot.img\n", ret);
		imgp_clear_state();
		imgp = imgp_init_state();
		if (!imgp) {
			ERR("Couldn't re-init image parser's state\n");
			goto done;
		}
		ret = tftp_request_file("boot.img", imgp_tftp_handler, imgp);
		if (ret < 0) {
			ERR("Second TFTP attempt failed with error %d\n", ret);
			goto done;
		}
	}

 done:
	imgp_clear_state();
	dhcp_send_release();
	net_exit();
	unit_handler_self(UNIT_CMD_FSBL_JUMP, NULL, 0);
	return ret;
};
