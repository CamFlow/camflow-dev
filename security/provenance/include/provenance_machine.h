// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 University of Cambridge, Harvard University, University of Bristol
 *
 * Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 */
#ifndef _PROVENANCE_MACHINE_H
#define _PROVENANCE_MACHINE_H

#include <uapi/linux/provenance.h>

#include <uapi/linux/provenance.h>

void init_prov_machine(void);
void refresh_prov_machine(void);
void print_prov_machine(void);
#endif
