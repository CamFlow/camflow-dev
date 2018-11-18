# Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
#
# Copyright (C) 2015-2018 University of Cambridge, Harvard University, University of Bristol
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

Dir.glob('./docs/dot/*.dot') do |item|
  puts item
  img = item.sub '.dot', '.png'
  img = img.sub '/dot/', '/img/'
  system('dot -Tpng '+item+' -o '+img)
end
