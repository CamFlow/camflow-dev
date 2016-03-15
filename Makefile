kernel-version=4.2.8
lsm-version=0.1
arch=x86_64

all: config compile

prepare: prepare_kernel prepare_us

prepare_kernel:
	mkdir -p build
	cd ./build && wget https://www.kernel.org/pub/linux/kernel/v4.x/linux-$(kernel-version).tar.xz && tar -xvJf linux-$(kernel-version).tar.xz && cd ./linux-$(kernel-version) && $(MAKE) mrproper


prepare_us:
	mkdir -p build
	cd ./build && git clone https://github.com/tfjmp/camflow-audit-lib.git
	cd ./build/camflow-audit-lib && $(MAKE) prepare

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
	cd ./build/linux-$(kernel-version) && sudo $(MAKE) headers_install ARCH=${arch} INSTALL_HDR_PATH=/usr
	cd ./build/camflow-audit-lib && $(MAKE) all

install_header:
	cd ./build/linux-$(kernel-version) && sudo $(MAKE) $(MAKE) headers_install ARCH=${arch} INSTALL_HDR_PATH=/usr

install:
	cd ./build/linux-$(kernel-version) && sudo $(MAKE) modules_install
	cd ./build/linux-$(kernel-version) && sudo $(MAKE) install

clean: clean_kernel clean_us

clean_kernel:
	cd ./build/linux-$(kernel-version) && $(MAKE) clean
	cd ./build/linux-$(kernel-version) && $(MAKE) mrproper

clean_us:
	cd ./build/camflow-audit-lib && $(MAKE) clean

patch:
	cd build && mkdir -p pristine
	cd build && tar -xvJf linux-$(kernel-version).tar.xz -C ./pristine
	cd build/pristine/linux-$(kernel-version) && $(MAKE) clean
	cd build/pristine/linux-$(kernel-version) && $(MAKE) mrproper
	cd ./build/linux-$(kernel-version) && $(MAKE) clean
	cd ./build/linux-$(kernel-version) && $(MAKE) mrproper
	diff -rcNP ./build/pristine/linux-$(kernel-version) ./build/linux-$(kernel-version) > ./build/patch-$(kernel-version)-v$(lsm-version); [ $$? -eq 1 ]
