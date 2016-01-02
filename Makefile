kernel-version=4.2.8

all: config compile

prepare:
	mkdir -p build
	cd ./build && wget https://www.kernel.org/pub/linux/kernel/v4.x/linux-$(kernel-version).tar.xz && tar -xvJf linux-$(kernel-version).tar.xz && cd ./linux-$(kernel-version) && $(MAKE) mrproper

config:
	cd ./build/linux-$(kernel-version) && cp -r ../../security .
	cd ./build/linux-$(kernel-version) && cp -r ../../include .
	cd ./build/linux-$(kernel-version) && cp ../../.config .config
	cd ./build/linux-$(kernel-version) && $(MAKE) menuconfig

compile_security:
	cd ./build/linux-$(kernel-version) && cp -r ../../security .
	cd ./build/linux-$(kernel-version) && cp -r ../../include .
	cd ./build/linux-$(kernel-version) && $(MAKE) security

compile:
	cd ./build/linux-$(kernel-version) && cp -r ../../security .
	cd ./build/linux-$(kernel-version) && cp -r ../../include .
	cd ./build/linux-$(kernel-version) && $(MAKE) security
	cd ./build/linux-$(kernel-version) && $(MAKE) -j4
	cd ./build/linux-$(kernel-version) && $(MAKE) -j4 modules

install:
	cd ./build/linux-$(kernel-version) && $(MAKE) modules_install
	cd ./build/linux-$(kernel-version) && $(MAKE) install

clean:
	cd ./build/linux-$(kernel-version) && $(MAKE) clean
	cd ./build/linux-$(kernel-version) && $(MAKE) mrproper
