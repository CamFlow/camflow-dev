# Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
#
# Copyright (C) 2015-2019 University of Cambridge, Harvard University, University of Bristol
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2, as
# published by the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.

class Graph
  def initialize
    @str = 'digraph RGL__DirectedAdjacencyGraph {'
    return self
  end

  def from_string str
    seen = []
    entries = str.split(',')
    entries.each do |e|
      e = e.strip.delete(' ')
      elements = e.match(/([a-z_]+)-([a-z_]+)->([a-z_]+)/)
      self.add_entity  elements[1] unless seen.include? elements[1]
      seen << elements[1] unless seen.include? elements[1]
      self.add_entity  elements[3] unless seen.include? elements[3]
      seen << elements[3] unless seen.include? elements[3]
      self.add_edge elements[1], elements[3], elements[2] unless seen.include? e
      seen << e unless seen.include? e
    end
  end

  def add_entity name
    if name == 'task'
      @str += name
      @str += '[fontsize = 8,label = '+name+',shape = rectangle, fillcolor="#e6e6fa", style = filled]'
      @str += "\n\n"
    elsif name == 'machine'
      @str += name
      @str += '[fontsize = 8,label = '+name+',shape = house, fillcolor="#ff8c00", style = filled]'
      @str += "\n\n"
    else
      @str += name
      @str += '[fontsize = 8,label = '+name+',shape = ellipse, fillcolor="#fffacd", style = filled]'
      @str += "\n\n"
    end
  end

  def add_edge from, to, name
    @str += from +' -> '+to
    @str += '[fontsize = 8,label = '+name+']'
    @str += "\n\n"
  end

  def get_dot
    @str += '}'
    return @str
  end

  def reset
    @str = 'digraph RGL__DirectedAdjacencyGraph {'
    return self
  end
end
