# Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
#
# Copyright (C) 2015-2019 University of Cambridge, Harvard University, University of Bristol
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

content = File.read('./test/flawfinder.txt')
new_content = content.gsub(/Lines analyzed = \d+ in approximately [\d.]+ seconds \(\d+ lines\/second\)/, 'Stat removed')
new_content = new_content.gsub(/Examining .\/security\/provenance\/include\/[\w]+.h/, 'File name removed')
new_content = new_content.gsub(/Examining .\/security\/provenance\/[\w]+.c/, 'File name removed')
File.open('./test/flawfinder.txt', 'w') do |file|
  file.puts new_content
end
