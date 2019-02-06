# Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
#
# Copyright (C) 2015-2019 University of Cambridge, Harvard University, University of Bristol
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

class Instruction
  def self.relation_to_str str
    File.readlines('./security/provenance/type.c').each do |line|
      relation = line.strip.match(/\s*static\s*const\s*char\s*RL_STR_(\w+)\[\]\s*=\s*"(\w+)"\s*;\s*\/\/\s*([\w\s]+)/)
      next unless !relation.nil?
      r = 'RL_' + relation.captures[0]
      if r == str
       return relation.captures[1]
      end
    end
    puts 'ERROR: unknown type!!!! '+str
  end

  def self.prov_to_type str
    if str == 'cprov' || str=='nprov' || str == 'old_prov' || str == 'pprov'
      return 'process_memory'
    elsif str == 'tprov' || str == 'ntprov'
      return 'task'
    elsif str == 'iprov' || str == 'iprova' || str == 'iprovb' || str == 'niprov' || str == 'inprov' || str == 'outprov' || str == 'oprov'
      return 'inode'
    elsif str == 'mprov'
      return 'msg'
    elsif str == 'sprov'
      return 'shm'
    elsif str == 'dprov'
      return 'directory'
    elsif str == 'iattrprov'
      return 'iattr'
    elsif str == 'bprov'
      return 'mmaped_file'
    elsif str == 'pckprov'
      return 'packet'
    else
      puts 'ERROR: unknown prov!!! '+str
    end
  end

  def self.version e
    if e == 'task'
      return 'task-'+ self.relation_to_str('RL_VERSION_TASK') + '->task'
    else
      return e+'-'+ self.relation_to_str('RL_VERSION') + '->' + e
    end
  end

  def self.uses_to_relation str
    str = str.strip.delete(' ')
    elements = str.match(/uses\(([A-Z_]+),([a-z_]+),([a-z_]+),([a-z_]+)/)
    relation = self.relation_to_str elements[1]
    a = self.prov_to_type elements[2]
    b = self.prov_to_type elements[3]
    c = self.prov_to_type elements[4]
    return a + '-' + relation + '->' + b + ',' + b + '-' + self.relation_to_str('RL_PROC_WRITE') + '->' + c + ',' + self.version(b) + ',' + self.version(c) + ',process_memory-'+self.relation_to_str('RL_SH_WRITE')+'->inode' +','+ self.version('inode')
  end

  def self.generates_to_relation str
    str = str.strip.delete(' ')
    elements = str.match(/generates\(([A-Z_]+),([a-z_]+),([a-z_]+),([a-z_]+)/)
    relation = self.relation_to_str elements[1]
    a = self.prov_to_type elements[2]
    b = self.prov_to_type elements[3]
    c = self.prov_to_type elements[4]
    return a + '-' + self.relation_to_str('RL_PROC_READ') + '->' + b + ',' + b + '-' + relation + '->' + c + ',' + self.version(b) + ',' + self.version(c) + ',inode-'+self.relation_to_str('RL_SH_READ')+'->process_memory' +','+ self.version('process_memory')
  end

  def self.derives_to_relation str
    str = str.strip.delete(' ')
    elements = str.match(/derives\(([A-Z_]+),&*([a-z_]+),([a-z_]+)/)
    relation = self.relation_to_str elements[1]
    a = self.prov_to_type elements[2]
    b = self.prov_to_type elements[3]
    return a + '-' + relation + '->' + b + ',' + self.version(b)
  end

  def self.informs_to_relation str
    str = str.strip.delete(' ')
    elements = str.match(/informs\(([A-Z_]+),&*([a-z_]+),([a-z_]+)/)
    relation = self.relation_to_str elements[1]
    a = self.prov_to_type elements[2]
    b = self.prov_to_type elements[3]
    return a + '-' + relation + '->' + b + ',' + self.version(b)
  end

  def self.uses_two_to_relation str
    str = str.strip.delete(' ')
    elements = str.match(/uses_two\(([A-Z_]+),&*([a-z_]+),([a-z_]+)/)
    relation = self.relation_to_str elements[1]
    a = self.prov_to_type elements[2]
    b = self.prov_to_type elements[3]
    return a + '-' + relation + '->' + b + ',' + self.version(b)
  end

  def self.influences_kernel_to_relation str
    str = str.strip.delete(' ')
    elements = str.match(/influences_kernel\(([A-Z_]+),&*([a-z_]+),([a-z_]+)/)
    relation = self.relation_to_str elements[1]
    a = self.prov_to_type elements[2]
    b = self.prov_to_type elements[3]
    return a + '-' + self.relation_to_str('RL_LOAD_FILE') + '->' + b + ',' + self.version(b) + ',' + b + '-' + self.relation_to_str('RL_LOAD_MODULE') + '-> machine' + ',' + self.version('machine')
  end

  def self.get_task_provenance_to_relation
    return 'machine-' + self.relation_to_str('RL_RAN_ON') + '->task'
  end

  def self.get_cred_provenance_to_relation
    return 'path-' + self.relation_to_str('RL_NAMED_PROCESS') + '->process_memory'
  end

  def self.inode_provenance_to_relation
    return 'path-' + self.relation_to_str('RL_NAMED') + '->inode'
  end

  def self.record_address_to_relation
    return 'address-' + self.relation_to_str('RL_NAMED') + '->inode'
  end

  def self.record_write_xattr_to_relation str
    str = str.strip.delete(' ')
    elements = str.match(/record_write_xattr\(([A-Z_]+)/)
    relation = self.relation_to_str elements[1]
    return 'process_memory-' + self.relation_to_str('RL_PROC_READ') + '->task,task-'+relation+'->xattr,xattr-'+self.relation_to_str('RL_RMVXATTR_INODE')+'->inode' + ',' + self.version('task') + ',' + self.version('inode') unless relation == 'setxattr'
    return 'process_memory-' + self.relation_to_str('RL_PROC_READ') + '->task,task-'+relation+'->xattr,xattr-'+self.relation_to_str('RL_SETXATTR_INODE')+'->inode' + ',' + self.version('task') + ',' + self.version('inode')
  end

  def self.record_terminate_to_relation str
    str = str.strip.delete(' ')
    elements = str.match(/record_terminate\(([A-Z_]+),([a-z_]+)/)
    relation = self.relation_to_str elements[1]
    a = self.prov_to_type elements[2]
    return a + '-' + relation + '->' + a
  end

  def self.record_read_xattr_to_relation
    return 'inode-' + self.relation_to_str('RL_GETXATTR_INODE') + '->xattr,xattr-'+self.relation_to_str('RL_GETXATTR')+'->task,task-'+self.relation_to_str('RL_PROC_WRITE')+'->process_memory' + ',' + self.version('task') + ',' + self.version('process_memory')
  end

  def self.record_packet_content_to_relation
    return 'packet_content-' + self.relation_to_str('RL_PCK_CNT') + '->packet'
  end

  def self.prov_record_args_to_relation
    return 'argv-' + self.relation_to_str('RL_ARG') + '->process_memory,envp-'+self.relation_to_str('RL_ENV')+'->process_memory'
  end
end
