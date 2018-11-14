/*
 *
 * Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
 *
 * Copyright (C) 2015-2018 University of Cambridge, Harvard University, University of Bristol
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 */
#ifndef _PROVENANCE_MACHINE_H
#define _PROVENANCE_MACHINE_H

#include <uapi/linux/provenance.h>

#include <uapi/linux/provenance.h>

extern union long_prov_elt prov_machine;

static void init_prov_machine(void) {
  struct new_utsname *uname = utsname();

  memset(&prov_machine.machine_info, 0, sizeof(prov_machine.machine_info));
  memcpy(&(prov_machine.machine_info.utsname), uname, sizeof(struct new_utsname));
  prov_machine.machine_info.cam_major = CAMFLOW_VERSION_MAJOR;
  prov_machine.machine_info.cam_minor = CAMFLOW_VERSION_MINOR;
  prov_machine.machine_info.cam_patch = CAMFLOW_VERSION_PATCH;
  memcpy(prov_machine.machine_info.commit, CAMFLOW_COMMIT, strlen(CAMFLOW_COMMIT));
  prov_type(&prov_machine) = ENT_MACHINE;
	node_identifier(&prov_machine).boot_id = prov_boot_id;
	node_identifier(&prov_machine).machine_id = prov_machine_id;
  set_is_long(&prov_machine);
}

static void print_prov_machine(void) {
  pr_info("Provenance: version %d.%d.%d", prov_machine.machine_info.cam_major, prov_machine.machine_info.cam_minor, prov_machine.machine_info.cam_patch);
  pr_info("Provenance: commit %s", prov_machine.machine_info.commit);
  pr_info("Provenance: sysname %s", prov_machine.machine_info.utsname.sysname);
  pr_info("Provenance: nodename %s", prov_machine.machine_info.utsname.nodename);
  pr_info("Provenance: release %s", prov_machine.machine_info.utsname.release);
  pr_info("Provenance: version %s", prov_machine.machine_info.utsname.version);
  pr_info("Provenance: machine %s", prov_machine.machine_info.utsname.machine);
  pr_info("Provenance: domainname %s", prov_machine.machine_info.utsname.domainname);
}
#endif
