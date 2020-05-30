kernel-version=5.6.13
lsm-version=0.6.7
arch=x86_64

cont-email="change@me.com"
cont-name="CHANGE ME"

all: config compile

prepare: prepare_kernel prepare_us

prepare_kernel_raw:
	mkdir -p build
	cd ./build && git clone -b v$(kernel-version) --single-branch git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
	cd ./build/linux-stable && $(MAKE) mrproper
	cd ./build && mkdir -p pristine
	cd ./build && cp -r ./linux-stable ./pristine

prepare_information_flow:
	mkdir -p build/linux-stable
	mkdir -p patches
	cd build && wget https://github.com/camflow/information-flow-patch/releases/download/$(kernel-version)/0001-information-flow.patch
	cd build/linux-stable && git apply ../0001-information-flow.patch

finalize:
	cd build/linux-stable && sed -i -e "s/EXTRAVERSION =/EXTRAVERSION = camflow$(lsm-version)/g" Makefile

prepare_kernel: prepare_kernel_raw prepare_information_flow finalize

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

copy_change: update_commit uncrustify uncrustify_clean
	cd ./build/linux-stable && cp -r ../../security .
	cd ./build/linux-stable && cp -r ../../include .

config_def:
	echo "Default method to retrieve configuration"
	cp -f /boot/config-$(shell uname -r) .config

config_pi:
	echo "Pi method to retrieve configuration"
	sudo modprobe configs
	zcat /proc/config.gz > /tmp/config.new
	cp -f /tmp/config.new .config

copy_config:
	test -f /boot/config-$(shell uname -r) && $(MAKE) config_def || $(MAKE) config_pi
	cd ./build/linux-stable && cp ../../.config .config

config: copy_change copy_config
	cd ./build/linux-stable && ./scripts/kconfig/streamline_config.pl > config_strip
	cd ./build/linux-stable &&  mv .config config_sav
	cd ./build/linux-stable &&  mv config_strip .config
	cd ./build/linux-stable && $(MAKE) menuconfig
	cd ./build/linux-stable && sed -i -e "s/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor\"/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,provenance\"/g" .config
	cd ./build/linux-stable && cp .config ../../.config
	cp -f .config ./scripts/.config

config_clang: copy_change copy_config
	cd ./build/linux-stable && ./scripts/kconfig/streamline_config.pl > config_strip
	cd ./build/linux-stable &&  mv .config config_sav
	cd ./build/linux-stable &&  mv config_strip .config
	cd ./build/linux-stable && $(MAKE) menuconfig CC=clang HOSTCC=clang
	cd ./build/linux-stable && sed -i -e "s/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor\"/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,provenance\"/g" .config
	cd ./build/linux-stable && cp .config ../../.config
	cp -f .config ./scripts/.config

config_travis: copy_change copy_config
	cd ./build/linux-stable && ./scripts/kconfig/streamline_config.pl > config_strip
	cd ./build/linux-stable &&  mv .config config_sav
	cd ./build/linux-stable &&  mv config_strip .config
	cd ./build/linux-stable && $(MAKE) olddefconfig
	cd ./build/linux-stable && $(MAKE) oldconfig
	cd ./build/linux-stable && sed -i -e "s/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor\"/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,provenance\"/g" .config

config_old: copy_change copy_config
	cd ./build/linux-stable && $(MAKE) olddefconfig
	cd ./build/linux-stable && $(MAKE) menuconfig
	cd ./build/linux-stable && sed -i -e "s/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor\"/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,provenance\"/g" .config


config_circle: copy_change
	cd ./build/linux-stable && $(MAKE) olddefconfig
	cd ./build/linux-stable && sed -i -e "s/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor\"/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,provenance\"/g" .config
	cd ./build/linux-stable && sed -i -e "s/CONFIG_DEBUG_INFO=y/CONFIG_DEBUG_INFO=n/g" .config
	cd ./build/linux-stable && sed -i -e "s/CONFIG_DEBUG_INFO_BTF=y/CONFIG_DEBUG_INFO_BTF=n/g" .config

config_circle_clang: copy_change
	cd ./build/linux-stable && $(MAKE) olddefconfig CC=clang HOSTCC=clang
	cd ./build/linux-stable && sed -i -e "s/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor\"/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,provenance\"/g" .config
	cd ./build/linux-stable && sed -i -e "s/CONFIG_DEBUG_INFO=y/CONFIG_DEBUG_INFO=n/g" .config
	cd ./build/linux-stable && sed -i -e "s/CONFIG_DEBUG_INFO_BTF=y/CONFIG_DEBUG_INFO_BTF=n/g" .config

hooklist:
	echo 'Generating HOOKS.md...'
	ruby ./scripts/hooklist.rb > docs/HOOKS.md

relationlist:
	echo 'Generating RELATIONS.md...'
	ruby ./scripts/relationlist.rb > docs/RELATIONS.md

vertexlist:
	echo 'Generating VERTICES.md...'
	ruby ./scripts/vertexlist.rb > docs/VERTICES.md

generate_dot:
	echo 'Generating dot files...'
	ruby ./scripts/graphs.rb

convert_png:
	echo 'Converting to png...'
	ruby ./scripts/convert.rb

doc: hooklist relationlist vertexlist generate_dot convert_png

update_commit:
	ruby ./scripts/commit.rb

compile: compile_security compile_kernel compile_us doc

compile_clang: compile_security_clang compile_kernel_clang compile_us_clang doc

compile_security_only:
	cd ./build/linux-stable && $(MAKE) security W=1

compile_security_only_clang:
	cd ./build/linux-stable && $(MAKE) security W=1 CC=clang HOSTCC=clang

compile_security: copy_change compile_security_only doc

compile_security_clang: copy_change compile_security_only_clang doc

compile_kernel: copy_change
	cd ./build/linux-stable && $(MAKE) -j16

compile_kernel_clang: copy_change
	cd ./build/linux-stable && $(MAKE) -j16 CC=clang HOSTCC=clang

compile_us:
	cd ./build/linux-stable && sudo $(MAKE) headers_install ARCH=${arch} INSTALL_HDR_PATH=/usr
	cd ./build/libprovenance && $(MAKE) clean
	cd ./build/libprovenance && $(MAKE) all

compile_us_clang:
	cd ./build/linux-stable && sudo $(MAKE) headers_install ARCH=${arch} INSTALL_HDR_PATH=/usr CC=clang HOSTCC=clang
	cd ./build/libprovenance && $(MAKE) clean
	cd ./build/libprovenance && $(MAKE) all

config_cross_pi: copy_change
	cd build/linux-stable && KERNEL=kernel7l
	cd build/linux-stable && make ARCH=arm CROSS_COMPILE=/usr/bin/arm-linux-gnu- menuconfig

compile_cross_pi:
	make -j 16 ARCH=arm CROSS_COMPILE=/usr/bin/arm-linux-gnu-
	make -j 16 ARCH=arm CROSS_COMPILE=/usr/bin/arm-linux-gnu- modules

install: install_kernel install_header install_us

install_clang: install_kernel_clang install_header_clang install_us

install_header:
	cd ./build/linux-stable && sudo $(MAKE) headers_install ARCH=${arch} INSTALL_HDR_PATH=/usr

install_header_clang:
	cd ./build/linux-stable && sudo $(MAKE) headers_install ARCH=${arch} INSTALL_HDR_PATH=/usr CC=clang HOSTCC=clang

install_kernel:
	cd ./build/linux-stable && sudo $(MAKE) modules_install
	cd ./build/linux-stable && sudo $(MAKE) install
	cd ./build/linux-stable && sudo cp -f .config /boot/config-$(kernel-version)camflow$(lsm-version)+

install_kernel_clang:
	cd ./build/linux-stable && sudo $(MAKE) modules_install CC=clang HOSTCC=clang
	cd ./build/linux-stable && sudo $(MAKE) install CC=clang HOSTCC=clang
	cd ./build/linux-stable && sudo cp -f .config /boot/config-$(kernel-version)camflow$(lsm-version)+

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
	cd ./build/linux-stable && $(MAKE) clean
	cd ./build/linux-stable && $(MAKE) mrproper

clean_us:
	cd ./build/libprovenance && $(MAKE) clean
	cd ./build/camconfd && $(MAKE) clean
	cd ./build/camflow-cli && $(MAKE) clean
	cd ./build/camflowd && $(MAKE) clean

delete_kernel:
	cd ./build && rm -rf ./pristine
	cd ./build && rm -rf ./linux-stable

delete_us:
	cd ./build && rm -rf ./camconfd
	cd ./build && rm -rf ./camflow-cli
	cd ./build && rm -rf ./camflowd
	cd ./build && rm -rf ./libprovenance

delete:
	rm -rf ./build

run_ltp:
	cd /opt/ltp && sudo ./runltp -R -o /tmp/ltp.txt -l /tmp/ltp.log -g /tmp/ltp.html -K /tmp/kernel

uncrustify:
	uncrustify -c uncrustify.cfg --replace security/provenance/fs.c
	uncrustify -c uncrustify.cfg --replace security/provenance/hooks.c
	uncrustify -c uncrustify.cfg --replace security/provenance/machine.c
	uncrustify -c uncrustify.cfg --replace security/provenance/netfilter.c
	uncrustify -c uncrustify.cfg --replace security/provenance/propagate.c
	uncrustify -c uncrustify.cfg --replace security/provenance/query.c
	uncrustify -c uncrustify.cfg --replace security/provenance/relay.c
	uncrustify -c uncrustify.cfg --replace security/provenance/type.c
	uncrustify -c uncrustify.cfg --replace security/provenance/memcpy_ss.c
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_filter.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_inode.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_machine.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_net.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_ns.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_policy.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_query.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_record.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_relay.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/provenance_task.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/memcpy_ss.h
	uncrustify -c uncrustify.cfg --replace include/linux/provenance_query.h
	uncrustify -c uncrustify.cfg --replace include/linux/provenance_types.h
	uncrustify -c uncrustify.cfg --replace include/uapi/linux/provenance_fs.h
	uncrustify -c uncrustify.cfg --replace include/uapi/linux/provenance_types.h
	uncrustify -c uncrustify.cfg --replace include/uapi/linux/provenance_utils.h
	uncrustify -c uncrustify.cfg --replace include/uapi/linux/provenance.h

uncrustify_clean:
	rm ./security/provenance/*backup*~
	rm ./security/provenance/include/*backup*~
	rm ./include/linux/*backup*~
	rm ./include/uapi/linux/*backup*~

patch: copy_change
	mkdir -p patches
	cd build/pristine/linux-stable && rm -f .config
	cd build/pristine/linux-stable && rm -f  config_sav
	cd build/pristine/linux-stable && rm -f  certs/signing_key.pem
	cd build/pristine/linux-stable && rm -f	certs/x509.genkey
	cd build/pristine/linux-stable && rm -f certs/signing_key.x509
	cd build/pristine/linux-stable && rm -f tools/objtool/arch/x86/insn/inat-tables.c
	cd build/pristine/linux-stable && $(MAKE) clean
	cd build/pristine/linux-stable && $(MAKE) mrproper
	cd build && wget https://github.com/camflow/information-flow-patch/releases/download/$(kernel-version)/0001-information-flow.patch
	cd build/pristine/linux-stable && git apply ../../0001-information-flow.patch
	cd build/pristine/linux-stable && git add .
	cd build/pristine/linux-stable && git commit -a -m 'information flow'
	cd build/pristine/linux-stable && cp -r ../../../security .
	cd build/pristine/linux-stable && cp -r ../../../include .
	cd build/pristine/linux-stable && git add .
	cd build/pristine/linux-stable && git commit -a -m 'camflow'
	cd build/pristine/linux-stable && git format-patch HEAD~~ -s
	cd build/pristine/linux-stable && cp -f *.patch ../../../patches/

test_patch:
	cd ./build/pristine/linux-stable && git apply ../../../patches/0001-information-flow.patch
	cd ./build/pristine/linux-stable && git apply ../../../patches/0002-camflow.patch

save_space:
	cd build/linux-stable && rm -rf .git
	cd build/pristine/linux-stable && rm -rf .git

prepare_dwarves:
	mkdir -p build
	cd ./build && git clone https://github.com/acmel/dwarves
	cd ./build/dwarves && git checkout v1.16
	cd ./build/dwarves && mkdir build
	cd ./build/dwarves/build && cmake -D__LIB=lib ..

install_dwarves:
	cd ./build/dwarves/build && make install
