#
# Makefile for Provenance LSM
#
obj-$(CONFIG_SECURITY_IFC) := ifc.o

ifc-y := hooks.o fs.o bridge.o exports.o

ccflags-y := -I$(srctree)/security/camflow -I$(srctree)/security/camflow/include -I$(srctree)/security/ifc/include -I$(srctree)/security/provenance/include
