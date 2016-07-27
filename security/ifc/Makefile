#
# Makefile for Provenance LSM
#
obj-$(CONFIG_SECURITY_IFC) := ifc.o

ifc-y := hooks.o fs.o bridge.o exports.o

ccflags-y := -I$(srctree)/security/camflow -I$(srctree)/security/camflow/include -I$(srctree)/security/selinux/include -I$(srctree)/security/ifc/include -I$(srctree)/security/provenance/include

quiet_cmd_flask = GEN     $(obj)/av_permissions.h
      cmd_flask = scripts/selinux/genheaders/genheaders $(obj)/av_permissions.h

 targets += av_permissions.h
