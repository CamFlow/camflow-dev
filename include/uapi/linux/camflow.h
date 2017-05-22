/*
 *
 * Author: Thomas Pasquier <thomas.pasquier@cl.cam.ac.uk>
 *
 * Copyright (C) 2016 University of Cambridge
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 */
#ifndef _UAPI_LINUX_CAMFLOW_H
#define _UAPI_LINUX_CAMFLOW_H

#define xstr(s) str(s)
#define str(s) # s

#define CAMFLOW_VERSION_MAJOR     0
#define CAMFLOW_VERSION_MINOR     3
#define CAMFLOW_VERSION_PATCH     1
#define CAMFLOW_VERSION_STR "v"xstr(CAMFLOW_VERSION_MAJOR)\
  "."xstr(CAMFLOW_VERSION_MINOR)\
  "."xstr(CAMFLOW_VERSION_PATCH)\

#endif
