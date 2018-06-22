puts "# CamFlow LSM hooks coverage\n\n"
puts "Automatically generated do not edit!\n\n"
puts "We build uppon [INRIA tools](http://kayrebt.gforge.inria.fr/).\n\n"
audit_related = ['audit_rule_init', 'audit_rule_match'] # we do not handle audit rules
capable_related = ['capable', 'capable_noaudit','capset','capget'] # we do not implement capability
secid_related = ['ipc_getsecid', 'inode_getsecid', 'task_getsecid', 'secid_to_secctx', 'release_secctx', 'cred_getsecid'] # no need to support secid related info as 1) we do not generate secid; 2) only one module can support it at any given time (right now SELinux)
path_related = ['path_truncate', 'path_mknod', 'path_mkdir', 'path_rmdir', 'path_unlink', 'path_symlink', 'path_link', 'path_rename', 'path_chmod', 'path_chown', 'path_chroot'] # supported by inode_xxx rather than path names
creds_related = ['prepare_creds'] # no need to support this one
sk_related = ['sk_free'] # not necessary due to implementation specific
file_related = ['file_alloc', 'file_free'] # we use underlying inode structure for tracking rather than file
to_remove = audit_related + capable_related + secid_related + path_related + creds_related + sk_related + file_related
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
    if clean == 'sock_rcv_skb' then
      clean = 'socket_sock_rcv_skb'
    end

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
