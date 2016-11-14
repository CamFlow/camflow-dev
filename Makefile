kernel-version=4.4.31
lsm-version=0.1.11
arch=x86_64

all: config compile

prepare: prepare_kernel prepare_us

prepare_kernel:
	mkdir -p build
	cd ./build && wget https://www.kernel.org/pub/linux/kernel/v4.x/linux-$(kernel-version).tar.xz && tar -xvJf linux-$(kernel-version).tar.xz && cd ./linux-$(kernel-version) && $(MAKE) mrproper


prepare_us:
	mkdir -p build
	cd ./build && git clone https://github.com/CamFlow/camflow-provenance-lib.git
	cd ./build/camflow-provenance-lib && $(MAKE) prepare
	cd ./build && git clone https://github.com/CamFlow/camflow-ifc-lib.git
	cd ./build/camflow-ifc-lib && $(MAKE) prepare
	cd ./build && git clone https://github.com/CamFlow/camflow-config.git
	cd ./build/camflow-config && $(MAKE) prepare

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
	cd ./build/camflow-provenance-lib && $(MAKE) clean
	cd ./build/camflow-provenance-lib && $(MAKE) all
	cd ./build/camflow-ifc-lib && $(MAKE) clean
	cd ./build/camflow-ifc-lib && $(MAKE) all

install_header:
	cd ./build/linux-$(kernel-version) && sudo $(MAKE) headers_install ARCH=${arch} INSTALL_HDR_PATH=/usr

install: install_kernel install_us

install_kernel:
	cd ./build/linux-$(kernel-version) && sudo $(MAKE) modules_install
	cd ./build/linux-$(kernel-version) && sudo $(MAKE) install

install_us:
	cd ./build/camflow-provenance-lib && $(MAKE) install
	cd ./build/camflow-ifc-lib && $(MAKE) install
	cd ./build/camflow-config && $(MAKE) all
	cd ./build/camflow-config && $(MAKE) install

clean: clean_kernel clean_us

clean_kernel:
	cd ./build/linux-$(kernel-version) && $(MAKE) clean
	cd ./build/linux-$(kernel-version) && $(MAKE) mrproper

clean_us:
	cd ./build/camflow-provenance-lib && $(MAKE) clean
	cd ./build/camflow-ifc-lib && $(MAKE) clean
	cd ./build/camflow-config && $(MAKE) clean

patch:
	cd build && mkdir -p pristine
	cd build && tar -xvJf linux-$(kernel-version).tar.xz -C ./pristine
	cd build/linux-$(kernel-version) && rm -f .config
	cd build/linux-$(kernel-version) && rm -f  config_sav
	cd build/linux-$(kernel-version) && rm -f  certs/signing_key.pem
	cd build/linux-$(kernel-version) && rm -f	certs/x509.genkey
	cd build/linux-$(kernel-version) && rm -f certs/signing_key.x509
	cd build && rm -f patch-$(kernel-version)-v$(lsm-version)
	cd build/pristine/linux-$(kernel-version) && $(MAKE) clean
	cd build/pristine/linux-$(kernel-version) && $(MAKE) mrproper
	cd ./build/linux-$(kernel-version) && $(MAKE) clean
	cd ./build/linux-$(kernel-version) && $(MAKE) mrproper
	cd ./build && diff -uprN ./pristine/linux-$(kernel-version) ./linux-$(kernel-version) > ./patch-$(kernel-version)-v$(lsm-version); [ $$? -eq 1 ]
