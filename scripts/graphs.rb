require './scripts/graph.rb'
require './scripts/instruction.rb'

g = Graph.new
hooks = Array.new

File.readlines('./security/provenance/hooks.c').each do |line|
  hook = line.match(/LSM_HOOK_INIT\s*\(\s*(\w+)\s*,\s*\w+\s*\)\s*,/)
  hooks << hook.captures[0] unless hook.nil?
end

str = ''
hook = ''
File.readlines('./security/provenance/hooks.c').each do |line|
  hooks.each do |h|
    if line.include?('provenance_'+h+'(')
      g.from_string(str) unless str == ''
      dot = g.get_dot unless str == ''
      File.open('/tmp/'+hook+'.dot', 'w') { |f| f.write(dot) } unless str == ''
      system('dot -Tpng /tmp/'+hook+'.dot -o ./docs/img/'+hook+'.png')  unless str == ''
      g.reset unless str == ''
      hook = h
      str = ''
    end
  end
  if line.include?('uses(')
    str += ',' unless str == ''
    str += Instruction.uses_to_relation(line)
  elsif line.include?('generates(')
    str += ',' unless str == ''
    str += Instruction.generates_to_relation(line)
  elsif line.include?('derives(')
    str += ',' unless str == ''
    str += Instruction.derives_to_relation(line)
  elsif line.include?('informs(')
    str += ',' unless str == ''
    str += Instruction.informs_to_relation(line)
  elsif line.include?('uses_two(')
    str += ',' unless str == ''
    str += Instruction.uses_two_to_relation(line)
  elsif line.include?('get_cred_provenance(')
    str += Instruction.get_cred_provenance_to_relation
  end
end
