/*
*
* /linux/ifc.h
*
* Author: Thomas Pasquier <tfjmp2@cam.ac.uk>
*
* Copyright (C) 2015 University of Cambridge
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation.
*
*/
#ifndef _UAPI_LINUX_IFC_H
#define _UAPI_LINUX_IFC_H

#define IFC_LABEL_MAX_SIZE  32
#define IFC_SECRECY         1
#define IFC_INTEGRITY       2

struct ifc_label{
  uint64_t array[IFC_LABEL_MAX_SIZE];
  uint8_t size;
};

struct ifc_context{
  struct ifc_label secrecy;
  struct ifc_label integrity;
  struct ifc_label secrecy_p;
  struct ifc_label integrity_p;
};

#endif
