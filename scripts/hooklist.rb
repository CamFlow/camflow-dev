puts "# LSM hooks implemented by CamFlow\n\n"
puts "Automatically generated do not edit!\n\n"
puts '```'
File.readlines('./security/provenance/hooks.c').each do |line|
  hook = line.match(/LSM_HOOK_INIT\s*\(\s*(\w+)\s*,\s*\w+\s*\)\s*,/)
  puts '- ' + hook.captures[0] unless hook.nil?
end
puts '```'
