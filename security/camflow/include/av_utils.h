/*
*
* security/camflow/include/av_utils.h
*
* Author: Thomas Pasquier <tfjmp@seas.harvard.edu>
*
* Copyright (C) 2016 Harvard University
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation.
*
*/

#ifndef _AV_UTILS_PROVENANCE_H
#define _AV_UTILS_PROVENANCE_H

// we depend on security/selinux/av_permssion.h
#include "av_permissions.h"

static inline uint32_t file_mask_to_perms(int mode, int mask){
  uint32_t av = 0;

  if (!S_ISDIR(mode)) {
    if (mask & MAY_EXEC)
      av |= FILE__EXECUTE;
    if (mask & MAY_READ)
      av |= FILE__READ;
    if (mask & MAY_APPEND)
      av |= FILE__APPEND;
    else if (mask & MAY_WRITE)
      av |= FILE__WRITE;
  } else {
    if (mask & MAY_EXEC)
      av |= DIR__SEARCH;
    if (mask & MAY_WRITE)
      av |= DIR__WRITE;
    if (mask & MAY_READ)
      av |= DIR__READ;
  }

  return av;
}

#endif
