#
# Makefile for Provenance LSM
#
obj-$(CONFIG_SECURITY_PROVENANCE) := provenance.o

provenance-y := provenance_relay.o hooks.o fs.o exports.o

ccflags-y := -I$(srctree)/security/camflow -I$(srctree)/security/camflow/include -I$(srctree)/security/selinux -I$(srctree)/security/ifc/include -I$(srctree)/security/provenance/include

quiet_cmd_flask = GEN     $(obj)/av_permissions.h
      cmd_flask = scripts/selinux/genheaders/genheaders $(obj)/av_permissions.h

 targets += av_permissions.h
