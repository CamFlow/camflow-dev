kernel-version=4.2.8

all: config compile

prepare: prepare_kernel prepare_us

prepare_kernel:
	mkdir -p build
	cd ./build && wget https://www.kernel.org/pub/linux/kernel/v4.x/linux-$(kernel-version).tar.xz && tar -xvJf linux-$(kernel-version).tar.xz && cd ./linux-$(kernel-version) && $(MAKE) mrproper


prepare_us:
	cd ./us && $(MAKE) prepare

config:
	cd ./build/linux-$(kernel-version) && cp -r ../../security .
	cd ./build/linux-$(kernel-version) && cp -r ../../include .
	cd ./build/linux-$(kernel-version) && cp ../../.config .config
	cd ./build/linux-$(kernel-version) && ./scripts/kconfig/streamline_config.pl > config_strip
	cd ./build/linux-$(kernel-version) &&  mv .config config_sav
	cd ./build/linux-$(kernel-version) &&  mv config_strip .config
	cd ./build/linux-$(kernel-version) && $(MAKE) menuconfig

compile: compile_security compile_kernel compile_us

compile_security:
	cd ./build/linux-$(kernel-version) && cp -r ../../security .
	cd ./build/linux-$(kernel-version) && cp -r ../../include .
	cd ./build/linux-$(kernel-version) && $(MAKE) security

compile_kernel:
	cd ./build/linux-$(kernel-version) && $(MAKE) -j4

compile_us:
	cd ./build/linux-$(kernel-version) && sudo $(MAKE) headers_install_all INSTALL_HDR_PATH=/usr
	cd ./us && $(MAKE) all

install_header:
	cd ./build/linux-$(kernel-version) && $(MAKE) headers_install_all INSTALL_HDR_PATH=/usr

install:
	cd ./build/linux-$(kernel-version) && $(MAKE) modules_install
	cd ./build/linux-$(kernel-version) && $(MAKE) install

clean: clean_kernel clean_us

clean_kernel:
	cd ./build/linux-$(kernel-version) && $(MAKE) clean
	cd ./build/linux-$(kernel-version) && $(MAKE) mrproper

clean_us:
	cd ./us && $(MAKE) clean
