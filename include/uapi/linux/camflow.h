/*
*
* /linux/ifc.h
*
* Author: Thomas Pasquier <tfjmp2@cam.ac.uk>
*
* Copyright (C) 2016 University of Cambridge
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation.
*
*/
#ifndef _UAPI_LINUX_CAMFLOW_H
#define _UAPI_LINUX_CAMFLOW_H

#define xstr(s) str(s)
#define str(s) #s

#define CAMFLOW_VERSION_MAJOR     0
#define CAMFLOW_VERSION_MINOR     1
#define CAMFLOW_VERSION_PATCH     0
#define CAMFLOW_VERSION_STAGE     0
#define CAMFLOW_VERSION_STR       "v"xstr(CAMFLOW_VERSION_MAJOR)"."xstr(CAMFLOW_VERSION_MINOR)"."xstr(CAMFLOW_VERSION_PATCH)"."xstr(CAMFLOW_VERSION_STAGE)


#endif
