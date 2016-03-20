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
#define IFC_SECRECY_P       3
#define IFC_INTEGRITY_P     4
#define IFC_SECRECY_N       5
#define IFC_INTEGRITY_N     6

#define IFC_ADD_TAG         1
#define IFC_REMOVE_TAG      2

typedef uint64_t tag_t;

struct ifc_label{
  tag_t array[IFC_LABEL_MAX_SIZE];
  uint8_t size;
};

struct ifc_context{
  struct ifc_label secrecy;
  struct ifc_label integrity;
  struct ifc_label secrecy_p;
  struct ifc_label integrity_p;
  struct ifc_label secrecy_n;
  struct ifc_label integrity_n;
};

struct ifc_struct{
  struct ifc_context context;
};

struct ifc_tag_msg{
  tag_t tag;
  uint8_t tag_type;
  uint8_t op;
  uint32_t pid;
};

#endif
