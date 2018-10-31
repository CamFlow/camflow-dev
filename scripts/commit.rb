hash = %x[git rev-parse HEAD]
command = "sed -i 's/#define CAMFLOW_COMMIT.*/#define CAMFLOW_COMMIT "+hash.chop!+"/' ./include/uapi/linux/provenance.h"
puts command
exec(command)
