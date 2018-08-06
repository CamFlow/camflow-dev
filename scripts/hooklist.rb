# Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
#
# Copyright (C) 2015-2018 University of Cambridge, Harvard University, University of Bristol
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

puts "# LSM hooks implemented by CamFlow\n\n"
puts "Automatically generated do not edit!\n\n"
puts 'LSM Hook|Graph|'
puts '--------|-----|'
File.readlines('./security/provenance/hooks.c').each do |line|
  hook = line.match(/LSM_HOOK_INIT\s*\(\s*(\w+)\s*,\s*\w+\s*\)\s*,/)
  h = hook.captures[0]   unless hook.nil?
  puts h + '| !['+h+' graph](./img/'+h+'.png)|'  unless hook.nil?
end
