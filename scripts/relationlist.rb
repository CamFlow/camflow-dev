# Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
#
# Copyright (C) 2015-2018 University of Cambridge, Harvard University, University of Bristol
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

puts "# Relations supported by CamFlow\n\n"
puts "Automatically generated do not edit!\n\n"
puts 'As defined in #include<linux/provenance_types.h>|string in configuration file and CLI|Description|'
puts '------------------------------------------------|------------------------------------|-----------|'
File.readlines('./security/provenance/type.c').each do |line|
  relation = line.strip.match(/\s*static\s*const\s*char\s*RL_STR_(\w+)\[\]\s*=\s*"(\w+)"\s*;\s*\/\/\s*([\w\s]+)/)
  puts 'RL_' + relation.captures[0] + '|' + relation.captures[1] + '|' + relation.captures[2] + "|\n" unless relation.nil?
end
