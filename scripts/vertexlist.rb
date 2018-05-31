puts "# Vertices supported by CamFlow\n\n"
puts "Automatically generated do not edit!\n\n"
puts '|As defined in #include<linux/provenance_types.h>|string in configuration file and CLI|'
puts '---------------------------------------------------------------------------------------'
File.readlines('./security/provenance/type.c').each do |line|
  relation = line.match(/\s*static\s*const\s*char\s*ND_STR_(\w+)\[\]\s*=\s*"(\w+)"\s*;/)
  if !relation.nil? && relation.captures[0] == 'TASK'
    puts '|ACT_' + relation.captures[0] + '|' + relation.captures[1] + '|' unless relation.nil?
  else
    puts '|ENT_' + relation.captures[0] + '|' + relation.captures[1] + '|' unless relation.nil?
  end
end
