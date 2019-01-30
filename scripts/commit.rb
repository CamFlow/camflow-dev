# Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
#
# Copyright (C) 2015-2019 University of Cambridge, Harvard University, University of Bristol
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

hash = %x[git rev-parse HEAD]
command = "sed -i 's/#define CAMFLOW_COMMIT.*/#define CAMFLOW_COMMIT \""+hash.chop!+"\"/' ./include/uapi/linux/provenance.h"
puts command
exec(command)
