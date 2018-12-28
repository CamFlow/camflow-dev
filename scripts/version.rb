# Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
#
# Copyright (C) 2015-2018 University of Cambridge, Harvard University, University of Bristol
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

File.readlines('../build/linux-stable/.config').each do |line|
  version = line.match(/# Linux\/x86 ([0-9.]+camflow[0-9.]+)/)
  v = version.captures[0]   unless version.nil?
  print v + '+' unless version.nil?
end
