/*
*
* Author: Thomas Pasquier <tfjmp@seas.harvard.edu>
*
* Copyright (C) 2016 Harvard University
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation; either version 2 of the License, or
*	(at your option) any later version.
*
*/
#ifndef CONFIG_SECURITY_PROVENANCE_NET
#include "provenance.h"

#define socket_inode_provenance(socket) (inode_provenance(SOCK_INODE(sock)))
#define sk_provenance(sk) (sk->sk_provenance)
#define socket_sk_provenance(socket) (sk_provenance(socket->sk))
#define sk_inode_provenance(sk) (socket_inode_provenance(sk->sk_socket))

#endif
