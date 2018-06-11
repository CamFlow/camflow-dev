puts "# CamFlow LSM hooks coverage\n\n"
puts "Automatically generated do not edit!\n\n"
puts "System Call|Called Hooks|Implemented Hooks|Coverage (%)|\n"
puts "-----------|------------|-----------------|------------|\n"
implemented_hooks = Array.new
File.readlines('./security/provenance/hooks.c').each do |line|
  hook = line.match(/LSM_HOOK_INIT\s*\(\s*(\w+)\s*,\s*\w+\s*\)\s*,/)
  implemented_hooks << hook.captures[0].strip unless hook.nil?
end
