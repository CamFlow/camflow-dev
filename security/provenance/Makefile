#
# Makefile for Provenance LSM
#
obj-$(CONFIG_SECURITY_PROVENANCE) := provenance.o

provenance-y := relay.o hooks.o query.o fs.o netfilter.o propagate.o type.o machine.o

ccflags-y := -I$(srctree)/security/provenance/include
