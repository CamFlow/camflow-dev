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
    if str == 'cprov' || str=='nprov'
      return 'process_memory'
    elsif str == 'tprov'
      return 'task'
    elsif str == 'iprov' || str == 'niprov'
      return 'inode'
    elsif str == 'mprov'
      return 'msg'
    elsif str == 'sprov'
      return 'shm'
    else
      puts 'ERROR: unknown prov!!! '+str
    end
  end

  def self.uses_to_relation str
    str = str.strip.delete(' ')
    elements = str.match(/uses\(([A-Z_]+),([a-z_]+),([a-z_]+),([a-z_]+)/)
    relation = self.relation_to_str elements[1]
    a = self.prov_to_type elements[2]
    b = self.prov_to_type elements[3]
    c = self.prov_to_type elements[4]
    return a + '-read_proc->' + b + ',' + b + '-' + relation + '->' + c
  end
end
