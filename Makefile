kernel-version=4.9.13
lsm-version=0.2.3
arch=x86_64

all: config compile

config_ubuntu:
	cp -f configs/config-ubuntu .config

config_fedora:
	cp -f configs/config-fedora .config

config_dev:
	cp -f configs/config-dev .config

prepare: prepare_kernel prepare_us

prepare_kernel:
	mkdir -p build
	cd ./build && wget https://www.kernel.org/pub/linux/kernel/v4.x/linux-$(kernel-version).tar.xz && tar -xJf linux-$(kernel-version).tar.xz && cd ./linux-$(kernel-version) && $(MAKE) mrproper

prepare_provenance:
	mkdir -p build
	cd ./build && git clone https://github.com/CamFlow/camflow-provenance-lib.git
	cd ./build/camflow-provenance-lib && $(MAKE) prepare

prepare_config:
	mkdir -p build
	cd ./build && git clone https://github.com/CamFlow/camflow-config.git
	cd ./build/camflow-config && $(MAKE) prepare

prepare_cli:
	mkdir -p build
	cd ./build && git clone https://github.com/CamFlow/camflow-cli.git
	cd ./build/camflow-cli && $(MAKE) prepare

prepare_us: prepare_provenance prepare_config prepare_cli

copy_change:
	cd ./build/linux-$(kernel-version) && cp -r ../../security .
	cd ./build/linux-$(kernel-version) && cp -r ../../include .

copy_config:
	cd ./build/linux-$(kernel-version) && cp ../../.config .config

config: copy_change copy_config
	cd ./build/linux-$(kernel-version) && ./scripts/kconfig/streamline_config.pl > config_strip
	cd ./build/linux-$(kernel-version) &&  mv .config config_sav
	cd ./build/linux-$(kernel-version) &&  mv config_strip .config
	cd ./build/linux-$(kernel-version) && $(MAKE) menuconfig

config_travis: copy_change copy_config
	cd ./build/linux-$(kernel-version) && $(MAKE) defconfig

compile: compile_security compile_kernel compile_us

compile_security: copy_change
	cd ./build/linux-$(kernel-version) && $(MAKE) security

compile_kernel: copy_change
	cd ./build/linux-$(kernel-version) && $(MAKE) -j4

compile_us:
	cd ./build/linux-$(kernel-version) && sudo $(MAKE) headers_install ARCH=${arch} INSTALL_HDR_PATH=/usr
	cd ./build/camflow-provenance-lib && $(MAKE) clean
	cd ./build/camflow-provenance-lib && $(MAKE) all

install_header:
	cd ./build/linux-$(kernel-version) && sudo $(MAKE) headers_install ARCH=${arch} INSTALL_HDR_PATH=/usr

install: install_kernel install_us

install_kernel:
	cd ./build/linux-$(kernel-version) && sudo $(MAKE) modules_install
	cd ./build/linux-$(kernel-version) && sudo $(MAKE) install

install_us:
	cd ./build/camflow-provenance-lib && $(MAKE) install
	cd ./build/camflow-config && $(MAKE) all
	cd ./build/camflow-config && $(MAKE) install
	cd ./build/camflow-cli && $(MAKE) all
	cd ./build/camflow-cli && $(MAKE) install

clean: clean_kernel clean_us

clean_kernel:
	cd ./build/linux-$(kernel-version) && $(MAKE) clean
	cd ./build/linux-$(kernel-version) && $(MAKE) mrproper

clean_us:
	cd ./build/camflow-provenance-lib && $(MAKE) clean
	cd ./build/camflow-config && $(MAKE) clean

delete_kernel:
	cd ./build && rm -rf ./linux-$(kernel-version)
	cd ./build && rm -f ./linux-$(kernel-version).tar.xz

test: copy_change
	@echo "Running sparse, result in /tmp/sparse.txt"
	-cd ./build/linux-$(kernel-version) && $(MAKE) C=2 security/provenance/ &> /tmp/sparse.txt
	@echo "Running checkpatch, result in /tmp/checkpatch.txt"
	-cd ./build/linux-$(kernel-version) && ./scripts/checkpatch.pl --file security/provenance/*.c > /tmp/checkpatch.txt
	-cd ./build/linux-$(kernel-version) && ./scripts/checkpatch.pl --file security/provenance/include/*.h >> /tmp/checkpatch.txt
	-cd ./build/linux-$(kernel-version) && ./scripts/checkpatch.pl --file include/uapi/linux/camflow.h >> /tmp/checkpatch.txt
	-cd ./build/linux-$(kernel-version) && ./scripts/checkpatch.pl --file include/uapi/linux/provenance.h >> /tmp/checkpatch.txt
	@echo "Running flawfinder, result in /tmp/flawfinder.txt"
	-cd ./build/linux-$(kernel-version) && flawfinder ./security/provenance > /tmp/flawfinder.txt

test_travis: copy_change
	-cd ./build/linux-$(kernel-version) && $(MAKE) C=2 security/provenance/
	@echo "Running checkpatch..."
	-cd ./build/linux-$(kernel-version) && ./scripts/checkpatch.pl --file security/provenance/*.c
	-cd ./build/linux-$(kernel-version) && ./scripts/checkpatch.pl --file security/provenance/include/*.h
	-cd ./build/linux-$(kernel-version) && ./scripts/checkpatch.pl --file include/uapi/linux/camflow.h
	-cd ./build/linux-$(kernel-version) && ./scripts/checkpatch.pl --file include/uapi/linux/provenance.h
	@echo "Running flawfinder..."
	-cd ./build/linux-$(kernel-version) && flawfinder ./security/provenance

uncrustify:
	uncrustify -c uncrustify.cfg --replace security/provenance/hooks.c
	uncrustify -c uncrustify.cfg --replace security/provenance/fs.c
	uncrustify -c uncrustify.cfg --replace security/provenance/netfilter.c
	uncrustify -c uncrustify.cfg --replace security/provenance/relay.c
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/av_utils.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_cgroup.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_filter.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_inode.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_long.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_net.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_relay.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_secctx.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_task.h
	uncrustify -c uncrustify.cfg --replace include/linux/cred.h
	uncrustify -c uncrustify.cfg --replace include/linux/fs.h
	uncrustify -c uncrustify.cfg --replace include/linux/ipc.h
	uncrustify -c uncrustify.cfg --replace include/linux/lsm_hooks.h
	uncrustify -c uncrustify.cfg --replace include/linux/msg.h
	uncrustify -c uncrustify.cfg --replace include/net/sock.h
	uncrustify -c uncrustify.cfg --replace include/uapi/linux/camflow.h
	uncrustify -c uncrustify.cfg --replace include/uapi/linux/provenance.h
	uncrustify -c uncrustify.cfg --replace include/uapi/linux/xattr.h

patch:
	cd build && mkdir -p pristine
	cd build && tar -xJf linux-$(kernel-version).tar.xz -C ./pristine
	cd build/linux-$(kernel-version) && rm -f .config
	cd build/linux-$(kernel-version) && rm -f  config_sav
	cd build/linux-$(kernel-version) && rm -f  certs/signing_key.pem
	cd build/linux-$(kernel-version) && rm -f	certs/x509.genkey
	cd build/linux-$(kernel-version) && rm -f certs/signing_key.x509
	cd build/linux-$(kernel-version) && rm -f tools/objtool/arch/x86/insn/inat-tables.c
	cd build && rm -f patch-$(kernel-version)-v$(lsm-version)
	cd build/pristine/linux-$(kernel-version) && $(MAKE) clean
	cd build/pristine/linux-$(kernel-version) && $(MAKE) mrproper
	cd ./build/linux-$(kernel-version) && $(MAKE) clean
	cd ./build/linux-$(kernel-version) && $(MAKE) mrproper
	cd ./build && diff -uprN -b -B ./pristine/linux-$(kernel-version) ./linux-$(kernel-version) > ./patch-$(kernel-version)-v$(lsm-version); [ $$? -eq 1 ]
