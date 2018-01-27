/*
 *
 * Author: Thomas Pasquier <thomas.pasquier@cl.cam.ac.uk>
 *
 * Copyright (C) 2015-2018 University of Cambridge, Harvard University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 */
#ifndef _PROVENANCE_TYPES_H
#define _PROVENANCE_TYPES_H

const char* relation_str(uint64_t type);
uint64_t relation_id(const char* str);
const char* node_str(uint64_t type);
uint64_t node_id(const char* str);

#endif /* _PROVENANCE_TYPES_H */
