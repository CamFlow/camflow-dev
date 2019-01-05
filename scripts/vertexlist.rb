# Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
#
# Copyright (C) 2015-2019 University of Cambridge, Harvard University, University of Bristol
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

puts "# Vertices supported by CamFlow\n\n"
puts "Automatically generated do not edit!\n\n"
puts 'As defined in #include<linux/provenance_types.h>|String in configuration file and CLI|Desciption|'
puts '------------------------------------------------|------------------------------------|----------|'
File.readlines('./security/provenance/type.c').each do |line|
  vertex = line.strip.match(/\s*static\s*const\s*char\s*ND_STR_(\w+)\[\]\s*=\s*"(\w+)"\s*;\s*\/\/\s*([\w\s]+)/)
  if !vertex.nil? && vertex.captures[0] == 'TASK'
    puts 'ACT_' + vertex.captures[0] + '|' + vertex.captures[1] + '|' + vertex.captures[2] + "|\n" unless vertex.nil?
  else
    puts 'ENT_' + vertex.captures[0] + '|' + vertex.captures[1] + '|' + vertex.captures[2] + "|\n" unless vertex.nil?
  end
end
