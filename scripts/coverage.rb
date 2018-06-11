puts "# CamFlow LSM hooks coverage\n\n"
puts "Automatically generated do not edit!\n\n"

to_remove = ['audit_rule_match', 'capable', 'capable_noaudit', 'inode_getsecid', 'task_getsecid', 'secid_to_secctx', 'release_secctx']
puts 'The following hooks are ignored in this report: '+to_remove.to_s+"\n\n"

puts "System Call|Hooks Called|Hooks Implemented|Hooks Not Implemented|Coverage (implemented / total)|\n"
puts "-----------|------------|-----------------|---------------------|------------------------------|\n"
implemented_hooks = Array.new
File.readlines('./security/provenance/hooks.c').each do |line|
  hook = line.match(/LSM_HOOK_INIT\s*\(\s*(\w+)\s*,\s*\w+\s*\)\s*,/)
  implemented_hooks << hook.captures[0].gsub('_security', '').strip unless hook.nil?
end
File.readlines('./scripts/syshooks.txt').each do |line|
  used = 0
  implemented = 0
  a_used = Array.new
  a_implemented = Array.new
  hook_list = line.match(/[\w]+\s\[([\w',\s]*)\]/)
  hooks = Array.new
  hooks = hook_list.captures[0].split(',') unless hook_list.nil?
  hooks.each do |hook|
    clean = hook.match(/u'([\w]+)'/).captures[0].gsub('security_', '').strip

    a_used << clean unless to_remove.include?(clean)
    used = used + 1 unless to_remove.include?(clean)

    implemented = implemented + 1 unless !implemented_hooks.include?(clean)
    a_implemented << clean unless !implemented_hooks.include?(clean)
  end
  call = line.match(/([\w]+)/)
  call_name = ''
  call_name = call.captures[0].strip unless call.nil?
  puts call_name + '|' + a_used.to_s + '|' + a_implemented.to_s + '|' + (a_used - a_implemented).to_s + '|' + implemented.to_s + '/' + used.to_s + "|\n"
end
