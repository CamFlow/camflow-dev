// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2016 University of Cambridge,
 * Copyright (C) 2016-2017 Harvard University,
 * Copyright (C) 2017-2018 University of Cambridge,
 * Copyright (C) 2018-2020 University of Bristol
 *
 * Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 */
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <asm/bug.h>

#include "include/memcpy_ss.h"

#define RSIZE_MAX_MEM (256UL << 20)   // 256MB

int __memcpy_ss(void *dest, __kernel_size_t dmax,
		const void *src, __kernel_size_t smax)
{
	uint8_t *dp = dest;
	const uint8_t *sp = src;

	if (WARN_ON(!dp)) {
		pr_err("%s: dest is null.", __func__);
		return -EFAULT;
	}
	if (WARN_ON(dmax == 0)) {
		pr_err("%s: dmax is 0.", __func__);
		return -EINVAL;
	}
	if (WARN_ON(dmax > RSIZE_MAX_MEM)) {
		pr_err("%s: dmax is too large.", __func__);
		return -EINVAL;
	}
	if (WARN_ON(!sp)) {
		pr_err("%s: sp is null.", __func__);
		memset(dp, 0, dmax);
		return -EFAULT;
	}
	if (WARN_ON(smax == 0)) { // nothing to copy
		pr_err("%s: smax is 0.", __func__);
		memset(dp, 0, dmax);
		return 0;
	}
	if (WARN_ON(smax > dmax)) {
		pr_err("%s: smax greater than dmax.", __func__);
		memset(dp, 0, dmax);
		return -EINVAL;
	}
	// check for overlap
	if (WARN_ON(((dp > sp) && (dp < (sp + smax))) ||
		    ((sp > dp) && (sp < (dp + smax))))) {
		pr_err("%s: dest and src overlap.", __func__);
		memset(dp, 0, dmax);
		return -EINVAL;
	}
	memcpy(dp, sp, smax);
	return 0;
}
