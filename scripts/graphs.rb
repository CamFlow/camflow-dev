# Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
#
# Copyright (C) 2015-2019 University of Cambridge, Harvard University, University of Bristol
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

require './scripts/graph.rb'
require './scripts/instruction.rb'

puts 'Building hooks provenance model...'
g = Graph.new
hooks = Array.new
hook_map = Hash.new

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
    File.open('./docs/dot/'+hook+'.dot', 'w') { |f| f.write(dot) } unless str == ''
    system('dot -Tpng ./docs/dot/'+hook+'.dot -o ./docs/img/'+hook+'.png')  unless str == ''
    if hook == 'socket_sendmsg' || hook == 'socket_recvmsg'
      system('dot -Tpng ./docs/dot/'+hook+'.dot -o ./docs/img/'+hook+'_always.png')  unless str == ''
      hook_map[hook+'_always'] = str unless str == ''
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
      File.open('./docs/dot/'+hook+'.dot', 'w') { |f| f.write(dot) } unless str == ''
      puts hook
      if hook == 'socket_sendmsg' || hook == 'socket_recvmsg'
        File.open('./docs/dot/'+hook+'_always.dot', 'w') { |f| f.write(dot) } unless str == ''
        hook_map[hook] = str unless str == ''
        hook_map[hook+'_always'] = str unless str == ''
      elsif hook == 'inode_link'
        File.open('./docs/dot/inode_rename.dot', 'w') { |f| f.write(dot) } unless str == ''
        hook_map[hook] = str unless str == ''
        hook_map['inode_rename'] = str unless str == ''
      elsif hook == '__mq_msgsnd'
        File.open('./docs/dot/msg_queue_msgsnd.dot', 'w') { |f| f.write(dot) } unless str == ''
        File.open('./docs/dot/mq_timedsend.dot', 'w') { |f| f.write(dot) } unless str == ''
        hook_map['msg_queue_msgsnd'] = str unless str == ''
        hook_map['mq_timedsend'] = str unless str == ''
      elsif hook == '__mq_msgrcv'
        File.open('./docs/dot/msg_queue_msgrcv.dot', 'w') { |f| f.write(dot) } unless str == ''
        File.open('./docs/dot/mq_timedreceive.dot', 'w') { |f| f.write(dot) } unless str == ''
        hook_map['msg_queue_msgrcv'] = str unless str == ''
        hook_map['mq_timedreceive'] = str unless str == ''
      elsif hook == 'msg_queue_msgrcv' || hook == 'mq_timedreceive' || hook == 'mq_timedsend' || hook == 'msg_queue_msgsnd'
        puts 'Skipping '+hook
      else
        hook_map.store(hook, str) unless str == ''
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
  elsif line.include?('influences_kernel(')
    str += ',' unless str == ''
    str += Instruction.influences_kernel_to_relation(line)
  elsif line.include?('get_task_provenance(')
    str += ',' unless str == ''
    str += Instruction.get_task_provenance_to_relation
  elsif line.include?('record_address(')
    str += ',' unless str == ''
    str += Instruction.record_address_to_relation
  elsif line.include?('record_write_xattr(')
    str += ',' unless str == ''
    str += Instruction.record_write_xattr_to_relation(line)
  elsif line.include?('record_read_xattr(')
    str += ',' unless str == ''
    str += Instruction.record_read_xattr_to_relation
  elsif line.include?('record_packet_content(')
    str += ',' unless str == ''
    str += Instruction.record_packet_content_to_relation
  elsif line.include?('prov_record_args(')
    str += ',' unless str == ''
    str += Instruction.prov_record_args_to_relation
  elsif line.include?('record_terminate(')
    str += ',' unless str == ''
    str += Instruction.record_terminate_to_relation(line)
  end
end

audit_related = ['audit_rule_init', 'audit_rule_match'] # we do not handle audit rules
capable_related = ['capable', 'capable_noaudit','capset','capget'] # we do not implement capability
secid_related = ['ipc_getsecid', 'inode_getsecid', 'task_getsecid', 'secid_to_secctx', 'release_secctx', 'cred_getsecid'] # no need to support secid related info as 1) we do not generate secid; 2) only one module can support it at any given time (right now SELinux)
path_related = ['path_truncate', 'path_mknod', 'path_mkdir', 'path_rmdir', 'path_unlink', 'path_symlink', 'path_link', 'path_rename', 'path_chmod', 'path_chown', 'path_chroot'] # supported by inode_xxx rather than path names
creds_related = [] # ['prepare_creds'] # no need to support this one
sk_related = ['sk_free'] # not necessary due to implementation specific
file_related = ['file_alloc', 'file_free'] # we use underlying inode structure for tracking rather than file
to_remove = audit_related + capable_related + secid_related + path_related + creds_related + sk_related + file_related
to_remove.sort!

implemented_hooks = Array.new
File.readlines('./security/provenance/hooks.c').each do |line|
  hook = line.match(/LSM_HOOK_INIT\s*\(\s*(\w+)\s*,\s*\w+\s*\)\s*,/)
  implemented_hooks << hook.captures[0].gsub('_security', '').strip unless hook.nil?
end
if File.file?('./scripts/syshooks.txt')
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
      if clean == 'sock_rcv_skb' then
        clean = 'socket_sock_rcv_skb'
      elsif clean == 'prepare_creds'
        clean = 'cred_prepare'
      end

      a_used << clean unless to_remove.include?(clean)
      used = used + 1 unless to_remove.include?(clean)

      implemented = implemented + 1 unless !implemented_hooks.include?(clean)
      a_implemented << clean unless !implemented_hooks.include?(clean)
    end
    call = line.match(/([\w]+)/)
    call_name = ''
    call_name = call.captures[0].strip unless call.nil?
    a_used.sort!
    a_implemented.sort!

    puts call_name
    str = ''
    a_implemented.each do |h|
      if hook_map.key? h
        puts h
        str += ',' unless str == ''
        str += hook_map[h] unless hook_map[h].nil?
      end
    end
    g.from_string(str) unless str == ''
    dot = g.get_dot unless str == ''
    g.reset unless str == ''
    File.open('./docs/dot/'+call_name+'.dot', 'w') { |f| f.write(dot) } unless str == ''
  end
end
