File.readlines('../build/linux-stable/.config').each do |line|
  version = line.match(/# Linux\/x86 ([0-9.]+camflow[0-9.]+)/)
  v = version.captures[0]   unless version.nil?
  print v + '+' unless version.nil?
end
