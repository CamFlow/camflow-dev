kernel-version=4.14.12
lsm-version=0.3.10
arch=x86_64


cont-email != $(git log --format="%ae" HEAD^!)
cont-name != $(git log --format="%ae" HEAD^!)

all: config compile

prepare: prepare_kernel prepare_us

prepare_kernel:
	mkdir -p build
	cd ./build && wget https://www.kernel.org/pub/linux/kernel/v4.x/linux-$(kernel-version).tar.xz && tar -xJf linux-$(kernel-version).tar.xz && cd ./linux-$(kernel-version) && $(MAKE) mrproper
	cd ./build/linux-$(kernel-version) && sed -i -e "s/EXTRAVERSION =/EXTRAVERSION = camflow$(lsm-version)/g" Makefile
	cd ./build && git clone https://github.com/CamFlow/information-flow-patch.git
	cd ./build/information-flow-patch && git checkout $(kernel-version)
	cd ./build && mkdir -p ./information-flow-patch/build
	cd ./build && cp -f linux-$(kernel-version).tar.xz ./information-flow-patch/build/linux-$(kernel-version).tar.xz
	cd ./build/information-flow-patch/build && tar -xJf linux-$(kernel-version).tar.xz && cd ./linux-$(kernel-version) && $(MAKE) mrproper
	cd ./build/information-flow-patch && $(MAKE) patch
	cd ./build/linux-$(kernel-version) && patch -p2 < ../information-flow-patch/output/patch-$(kernel-version)-flow-friendly

prepare_provenance:
	mkdir -p build
	cd ./build && git clone https://github.com/CamFlow/libprovenance.git
	cd ./build/libprovenance && $(MAKE) prepare

prepare_config:
	mkdir -p build
	cd ./build && git clone https://github.com/CamFlow/camconfd.git
	cd ./build/camconfd && $(MAKE) prepare

prepare_cli:
	mkdir -p build
	cd ./build && git clone https://github.com/CamFlow/camflow-cli.git
	cd ./build/camflow-cli && $(MAKE) prepare

prepare_service:
	mkdir -p build
	cd ./build && git clone https://github.com/CamFlow/camflowd.git
	cd ./build/camflowd && $(MAKE) prepare

prepare_smatch:
	mkdir -p build
	cd ./build && git clone git://repo.or.cz/smatch.git
	cd ./build/smatch && git checkout 1.60
	cd ./build/smatch && $(MAKE)

prepare_ltp:
	mkdir -p build
	cd ./build && git clone https://github.com/linux-test-project/ltp.git
	cd ./build/ltp && $(MAKE) autotools
	cd ./build/ltp && ./configure
	cd ./build/ltp && $(MAKE)
	cd ./build/ltp && sudo $(MAKE) install

prepare_us: prepare_provenance prepare_config prepare_cli prepare_service

copy_change:
	cd ./build/linux-$(kernel-version) && cp -r ../../security .
	cd ./build/linux-$(kernel-version) && cp -r ../../include .

copy_config:
	cp -f /boot/config-$(shell uname -r) .config
	sed -i -e "s/CONFIG_DRM_VBOXVIDEO=m/# CONFIG_DRM_VBOXVIDEO is not set/g" ./.config
	cd ./build/linux-$(kernel-version) && cp ../../.config .config

config: copy_change copy_config
	cd ./build/linux-$(kernel-version) && ./scripts/kconfig/streamline_config.pl > config_strip
	cd ./build/linux-$(kernel-version) &&  mv .config config_sav
	cd ./build/linux-$(kernel-version) &&  mv config_strip .config
	cd ./build/linux-$(kernel-version) && $(MAKE) menuconfig

config_travis: copy_change copy_config
	cd ./build/linux-$(kernel-version) && ./scripts/kconfig/streamline_config.pl > config_strip
	cd ./build/linux-$(kernel-version) &&  mv .config config_sav
	cd ./build/linux-$(kernel-version) &&  mv config_strip .config
	cd ./build/linux-$(kernel-version) && $(MAKE) olddefconfig
	cd ./build/linux-$(kernel-version) && $(MAKE) oldconfig

config_old: copy_change copy_config
	 cd ./build/linux-$(kernel-version) && $(MAKE) olddefconfig
	 cd ./build/linux-$(kernel-version) && $(MAKE) menuconfig

compile: compile_security compile_kernel compile_us

compile_security_only:
	cd ./build/linux-$(kernel-version) && $(MAKE) security W=1

compile_security: copy_change compile_security_only

compile_kernel: copy_change
	cd ./build/linux-$(kernel-version) && $(MAKE) -j4

compile_us:
	cd ./build/linux-$(kernel-version) && sudo $(MAKE) headers_install ARCH=${arch} INSTALL_HDR_PATH=/usr
	cd ./build/libprovenance && $(MAKE) clean
	cd ./build/libprovenance && $(MAKE) all

install_header:
	cd ./build/linux-$(kernel-version) && sudo $(MAKE) headers_install ARCH=${arch} INSTALL_HDR_PATH=/usr

install: install_kernel install_header install_us

install_kernel:
	cd ./build/linux-$(kernel-version) && sudo $(MAKE) modules_install
	cd ./build/linux-$(kernel-version) && sudo $(MAKE) install
	cd ./build/linux-$(kernel-version) && sudo cp -f .config /boot/config-$(kernel-version)camflow_$(lsm-version)

install_us:
	cd ./build/libprovenance && $(MAKE) install
	cd ./build/camconfd && $(MAKE) all
	cd ./build/camconfd && $(MAKE) install
	cd ./build/camflowd && $(MAKE) all
	cd ./build/camflowd && $(MAKE) install
	cd ./build/camflow-cli && $(MAKE) all
	cd ./build/camflow-cli && $(MAKE) install

clean: clean_kernel clean_us

clean_kernel:
	cd ./build/linux-$(kernel-version) && $(MAKE) clean
	cd ./build/linux-$(kernel-version) && $(MAKE) mrproper

clean_us:
	cd ./build/libprovenance && $(MAKE) clean
	cd ./build/camconfd && $(MAKE) clean
	cd ./build/camflow-cli && $(MAKE) clean
	cd ./build/camflowd && $(MAKE) clean

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
	@echo "Running smatch..."
	-cd ./build/linux-$(kernel-version) && $(MAKE) clean
	-cd ./build/linux-$(kernel-version) && $(MAKE) security CHECK="../smatch/smatch -p=kernel" C=1
	@echo "Running coccinelle"
	-cd ./build/linux-$(kernel-version) && sed -i '/options = --use-gitgrep/d' .cocciconfig
	-cd ./build/linux-$(kernel-version) && $(MAKE) coccicheck MODE=report M=security/provenance

run_ltp:
	cd /opt/ltp && sudo ./runltp -R -o /tmp/ltp.txt -l /tmp/ltp.log -g /tmp/ltp.html -K /tmp/kernel -a tfjmp@seas.harvard.edu

test_travis:
	@echo "Running sparse..."
	-cd ./build/linux-$(kernel-version) && $(MAKE) C=2 security/provenance/
	@echo "Running checkpatch..."
	-cd ./build/linux-$(kernel-version) && ./scripts/checkpatch.pl --file security/provenance/*.c
	-cd ./build/linux-$(kernel-version) && ./scripts/checkpatch.pl --file security/provenance/include/*.h
	-cd ./build/linux-$(kernel-version) && ./scripts/checkpatch.pl --file include/uapi/linux/camflow.h
	-cd ./build/linux-$(kernel-version) && ./scripts/checkpatch.pl --file include/uapi/linux/provenance.h
	@echo "Running flawfinder..."
	-cd ./build/linux-$(kernel-version) && flawfinder ./security/provenance

uncrustify:
	uncrustify -c uncrustify.cfg --replace security/provenance/fs.c
	uncrustify -c uncrustify.cfg --replace security/provenance/hooks.c
	uncrustify -c uncrustify.cfg --replace security/provenance/netfilter.c
	uncrustify -c uncrustify.cfg --replace security/provenance/propagate.c
	uncrustify -c uncrustify.cfg --replace security/provenance/query.c
	uncrustify -c uncrustify.cfg --replace security/provenance/relay.c
	uncrustify -c uncrustify.cfg --replace security/provenance/type.c
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_filter.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_inode.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_net.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_ns.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_policy.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_query.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_relay.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_task.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_types.h

patch: copy_change
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

prepare_release_travis:
	cp -f build/patch-$(kernel-version)-v$(lsm-version) patch

prepare_git:
	mkdir -p build
	cd build && git clone -b v$(kernel-version) git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git


patch_git:
	git config --global user.email $(cont-email)
	git config --global user.name $(cont-name)
	cd ./build/linux-stable && patch -p2 < ../information-flow-patch/output/patch-$(kernel-version)-flow-friendly
	cd ./build/linux-stable && git add .
	cd ./build/linux-stable && git commit -a -m 'information flow patch'
	cd ./build/linux-stable && cp -r ../../security .
	cd ./build/linux-stable && cp -r ../../include .
	cd ./build/linux-stable && git add .
	cd ./build/linux-stable && git commit -a -m 'camflow patch'
	cd ./build/linux-stable && git format-patch HEAD~~ -s

update_linuxkit:
	cd ./build && git clone https://github.com/CamFlow/linuxkit.git
	mkdir -p ./build/linuxkit/projects/camflow/kernel/patches-4.14.x
	cp ./build/linux-stable/0001-information-flow-patch.patch ./build/linuxkit/projects/camflow/kernel/patches-4.14.x/0001-information-flow-patch.patch
	cp ./build/linux-stable/0002-camflow-patch.patch ./build/linuxkit/projects/camflow/kernel/patches-4.14.x/0002-camflow-patch.patch
	cd ./build/linuxkit && git add .
	cd ./build/linuxkit && git commit -a -m "Travis updated camflow patch $(shell date --iso=seconds)"
