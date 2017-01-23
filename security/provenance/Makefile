#
# Makefile for Provenance LSM
#
obj-$(CONFIG_SECURITY_PROVENANCE) := provenance.o

provenance-y := relay.o hooks.o fs.o netfilter.o

ccflags-y := -I$(srctree)/security/provenance/include
