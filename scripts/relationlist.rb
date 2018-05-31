puts "# Relations supported by CamFlow\n\n"
puts "Automatically generated do not edit!\n\n"
puts 'As defined in #include<linux/provenance_types.h>|string in configuration file and CLI|'
puts '------------------------------------------------|------------------------------------|'
File.readlines('./security/provenance/type.c').each do |line|
  relation = line.match(/\s*static\s*const\s*char\s*RL_STR_(\w+)\[\]\s*=\s*"(\w+)"\s*;/)
  puts 'RL_' + relation.captures[0] + '|' + relation.captures[1] + + "|\n" unless relation.nil?
end
