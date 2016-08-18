#
# Makefile for Provenance LSM
#
obj-$(CONFIG_SECURITY_PROVENANCE) := provenance.o

provenance-y := relay.o hooks.o fs.o exports.o

ccflags-y := -I$(srctree)/security/camflow -I$(srctree)/security/camflow/include -I$(srctree)/security/ifc/include -I$(srctree)/security/provenance/include
