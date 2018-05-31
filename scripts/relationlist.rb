puts '#Relation supported by CamFlow'
puts 'Automatically generated do not edit!'
puts '|As defined in #include<linux/provenance_types.h>|string in configuration file and CLI|'
File.readlines('./security/provenance/type.c').each do |line|
  relation = line.match(/\s*static\s*const\s*char\s*RL_STR_(\w+)\[\]\s*=\s*"(\w+)"\s*;/)
  puts '|RL_' + relation.captures[0] + '|' + relation.captures[1] + '|' unless relation.nil?
end
