// SPDX-License-Identifier: GPL-2.0-only
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
#include "provenance.h"
#include "provenance_machine.h"
#include "memcpy_ss.h"

static union long_prov_elt __prov_machine;
union long_prov_elt *prov_machine;

void refresh_prov_machine(void)
{
	struct new_utsname *uname = utsname();

	__memcpy_ss(&(prov_machine->machine_info.utsname), sizeof(struct new_utsname), uname, sizeof(struct new_utsname));
	node_identifier(prov_machine).id = djb2_hash(CAMFLOW_COMMIT);
	node_identifier(prov_machine).boot_id = prov_boot_id;
	node_identifier(prov_machine).machine_id = prov_machine_id;
	clear_recorded(prov_machine);
}

void init_prov_machine(void)
{
	prov_machine = &__prov_machine;
	prov_machine->machine_info.cam_major = CAMFLOW_VERSION_MAJOR;
	prov_machine->machine_info.cam_minor = CAMFLOW_VERSION_MINOR;
	prov_machine->machine_info.cam_patch = CAMFLOW_VERSION_PATCH;
	__memcpy_ss(prov_machine->machine_info.commit, PROV_COMMIT_MAX_LENGTH, CAMFLOW_COMMIT, strnlen(CAMFLOW_COMMIT, PROV_COMMIT_MAX_LENGTH));
	prov_type(prov_machine) = AGT_MACHINE;
	node_identifier(prov_machine).version = 1;
	refresh_prov_machine();
	call_provenance_alloc(prov_machine);
}

void print_prov_machine(void)
{
	pr_info("Provenance: version %d.%d.%d", prov_machine->machine_info.cam_major, prov_machine->machine_info.cam_minor, prov_machine->machine_info.cam_patch);
	pr_info("Provenance: commit %s", prov_machine->machine_info.commit);
	pr_info("Provenance: sysname %s", prov_machine->machine_info.utsname.sysname);
	pr_info("Provenance: nodename %s", prov_machine->machine_info.utsname.nodename);
	pr_info("Provenance: release %s", prov_machine->machine_info.utsname.release);
	pr_info("Provenance: version %s", prov_machine->machine_info.utsname.version);
	pr_info("Provenance: machine %s", prov_machine->machine_info.utsname.machine);
	pr_info("Provenance: domainname %s", prov_machine->machine_info.utsname.domainname);
}
