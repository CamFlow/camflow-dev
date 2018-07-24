require './scripts/graph.rb'
require './scripts/instruction.rb'

puts 'Building hooks provenance model...'
g = Graph.new
hooks = Array.new

File.readlines('./security/provenance/hooks.c').each do |line|
  hook = line.match(/LSM_HOOK_INIT\s*\(\s*(\w+)\s*,\s*\w+\s*\)\s*,/)
  hooks << hook.captures[0] unless hook.nil?
end

str = ''
hook = ''
File.readlines('./security/provenance/hooks.c').each do |line|
  if  line.include?('int __mq_msgsnd(') || line.include?('int __mq_msgrcv(')
    g.from_string(str) unless str == ''
    dot = g.get_dot unless str == ''
    File.open('/tmp/'+hook+'.dot', 'w') { |f| f.write(dot) } unless str == ''
    system('dot -Tpng /tmp/'+hook+'.dot -o ./docs/img/'+hook+'.png')  unless str == ''
    if hook == 'socket_sendmsg' || hook == 'socket_recvmsg'
      system('dot -Tpng /tmp/'+hook+'.dot -o ./docs/img/'+hook+'_always.png')  unless str == ''
    end
    g.reset unless str == ''
    if line.include?('__mq_msgsnd(')
      hook = '__mq_msgsnd'
    elsif line.include?('__mq_msgrcv(')
      hook = '__mq_msgrcv'
    end
    str = ''
  end
  hooks.each do |h|
    if line.include?('provenance_'+h+'(')
      g.from_string(str) unless str == ''
      dot = g.get_dot unless str == ''
      File.open('/tmp/'+hook+'.dot', 'w') { |f| f.write(dot) } unless str == ''
      puts hook
      if hook == 'socket_sendmsg' || hook == 'socket_recvmsg'
        system('dot -Tpng /tmp/'+hook+'.dot -o ./docs/img/'+hook+'.png')  unless str == ''
        system('dot -Tpng /tmp/'+hook+'.dot -o ./docs/img/'+hook+'_always.png')  unless str == ''
      elsif hook == 'inode_link'
        system('dot -Tpng /tmp/'+hook+'.dot -o ./docs/img/'+hook+'.png')  unless str == ''
        system('dot -Tpng /tmp/'+hook+'.dot -o ./docs/img/inode_rename.png')  unless str == ''
      elsif hook == '__mq_msgsnd'
        system('dot -Tpng /tmp/'+hook+'.dot -o ./docs/img/msg_queue_msgsnd.png')  unless str == ''
        system('dot -Tpng /tmp/'+hook+'.dot -o ./docs/img/mq_timedsend.png')  unless str == ''
      elsif hook == '__mq_msgrcv'
        system('dot -Tpng /tmp/'+hook+'.dot -o ./docs/img/msg_queue_msgrcv.png')  unless str == ''
        system('dot -Tpng /tmp/'+hook+'.dot -o ./docs/img/mq_timedreceive.png')  unless str == ''
      elsif hook == 'msg_queue_msgrcv' || hook == 'mq_timedreceive' || hook == 'mq_timedsend' || hook == 'msg_queue_msgsnd'
        puts 'Skipping '+hook
      else
        system('dot -Tpng /tmp/'+hook+'.dot -o ./docs/img/'+hook+'.png')  unless str == ''
      end
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
    str += ',' unless str == ''
    str += Instruction.get_cred_provenance_to_relation
  elsif line.include?('inode_provenance(') && line.include?('true')
    str += ',' unless str == ''
    str += Instruction.inode_provenance_to_relation
  elsif line.include?('dentry_provenance(') && line.include?('true')
    str += ',' unless str == ''
    str += Instruction.inode_provenance_to_relation
  elsif line.include?('file_provenance(') && line.include?('true')
    str += ',' unless str == ''
    str += Instruction.inode_provenance_to_relation
  elsif line.include?('refresh_inode_provenance(')
    str += ',' unless str == ''
    str += Instruction.inode_provenance_to_relation
  elsif line.include?('provenance_record_address(')
    str += ',' unless str == ''
    str += Instruction.provenance_record_address_to_relation
  elsif line.include?('record_write_xattr(')
    str += ',' unless str == ''
    str += Instruction.record_write_xattr_to_relation(line)
  elsif line.include?('record_read_xattr(')
    str += ',' unless str == ''
    str += Instruction.record_read_xattr_to_relation
  elsif line.include?('provenance_packet_content(')
    str += ',' unless str == ''
    str += Instruction.provenance_packet_content_to_relation
  elsif line.include?('prov_record_args(')
    str += ',' unless str == ''
    str += Instruction.prov_record_args_to_relation
  elsif line.include?('record_terminate(')
    str += ',' unless str == ''
    str += Instruction.record_terminate_to_relation(line)
  end
end
