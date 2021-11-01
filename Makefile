kernel-version=5.13.9
lsm-version=0.8.0
arch=x86_64

all: config compile install

prepare: prepare_kernel prepare_us

prepare_kernel_raw:
	mkdir -p ~/build
	cd ~/build && git clone -b v$(kernel-version) --single-branch --depth 1 git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
	cd ~/build/linux-stable && $(MAKE) mrproper
	cd ~/build && mkdir -p pristine
	cd ~/build && cp -r ./linux-stable ./pristine

prepare_information_flow:
	mkdir -p patches
	rm -f ~/build//0001-information-flow.patch
	cd ~/build && wget https://github.com/camflow/information-flow-patch/releases/download/$(kernel-version)/0001-information-flow.patch
	cd ~/build/linux-stable && git apply --whitespace=fix --verbose ../0001-information-flow.patch

finalize:
	cd ~/build/linux-stable && sed -i -e "s/EXTRAVERSION =/EXTRAVERSION = camflow$(lsm-version)/g" Makefile

prepare_kernel: prepare_kernel_raw prepare_information_flow finalize

prepare_submodules:
	git submodule update --init --recursive

prepare_provenance:
	cd us-dependencies/libprovenance && $(MAKE) prepare

prepare_config:
	cd us-dependencies/camconfd && $(MAKE) prepare

prepare_cli:
	cd us-dependencies/camflow-cli && $(MAKE) prepare

prepare_service:
	cd us-dependencies/camflowd && $(MAKE) prepare

prepare_smatch:
	mkdir -p ~/build
	cd ~/build && git clone git://repo.or.cz/smatch.git
	cd ~/build/smatch && git checkout 1.71
	cd ~/build/smatch && $(MAKE)

prepare_sparse:
	mkdir -p ~/build
	cd ~/build && git clone git://git.kernel.org/pub/scm/devel/sparse/sparse.git
	cd ~/build/sparse && git checkout v0.6.1
	cd ~/build/sparse && make
	cd ~/build/sparse && sudo make install

prepare_tinkerbell:
	mkdir -p ~/build
	cd ~/build && git clone https://github.com/TinkerBellSystem/compiler
	cd ~/build/compiler && git checkout thomas
	cd ~/build/compiler && make prepare
	cd ~/build/compiler && make config
	cd ~/build && git clone https://github.com/TinkerBellSystem/graph-matching
	cd ~/build/graph-matching && git checkout thomas

prepare_ltp:
	mkdir -p ~/build
	cd ~/build && git clone https://github.com/linux-test-project/ltp.git
	cd ~/build/ltp && $(MAKE) autotools
	cd ~/build/ltp && ./configure
	cd ~/build/ltp && $(MAKE)
	cd ~/build/ltp && sudo $(MAKE) install

prepare_us: prepare_submodules prepare_provenance prepare_config prepare_cli prepare_service

prepare_update: prepare_kernel
	mv include/net/sock.h include/net/_sock.h
	cp ~/build/pristine/linux-stable/include/net/sock.h include/net/sock.h
	mv include/uapi/linux/xattr.h include/uapi/linux/_xattr.h
	cp ~/build/pristine/linux-stable/include/uapi/linux/xattr.h include/uapi/linux/xattr.h
	mv security/Kconfig security/_Kconfig
	cp ~/build/pristine/linux-stable/security/Kconfig security/Kconfig
	mv security/Makefile security/_Makefile
	cp ~/build/pristine/linux-stable/security/Makefile security/Makefile

copy_change: uncrustify uncrustify_clean
	cp -r ./security ~/build/linux-stable
	cp -r ./include ~/build/linux-stable

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
	cp .config ~/build/linux-stable/.config

config: copy_change copy_config
	cd ~/build/linux-stable && ./scripts/kconfig/streamline_config.pl > config_strip
	cd ~/build/linux-stable &&  mv .config config_sav
	cd ~/build/linux-stable &&  mv config_strip .config
	cd ~/build/linux-stable && $(MAKE) menuconfig
	cd ~/build/linux-stable && sed -i -e "s/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor\"/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,provenance\"/g" .config
	cp ~/build/linux-stable/.config .config
	cp -f .config ./scripts/.config

config_clang: copy_change copy_config
	cd ~/build/linux-stable && ./scripts/kconfig/streamline_config.pl > config_strip
	cd ~/build/linux-stable &&  mv .config config_sav
	cd ~/build/linux-stable &&  mv config_strip .config
	cd ~/build/linux-stable && $(MAKE) menuconfig CC=clang HOSTCC=clang
	cd ~/build/linux-stable && sed -i -e "s/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor\"/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,provenance\"/g" .config
	cp ~/build/linux-stable/.config .config
	cp -f .config ./scripts/.config

config_travis: copy_change copy_config
	cd ~/build/linux-stable && ./scripts/kconfig/streamline_config.pl > config_strip
	cd ~/build/linux-stable &&  mv .config config_sav
	cd ~/build/linux-stable &&  mv config_strip .config
	cd ~/build/linux-stable && $(MAKE) olddefconfig
	cd ~/build/linux-stable && $(MAKE) oldconfig
	cd ~/build/linux-stable && sed -i -e "s/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor\"/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,provenance\"/g" .config

config_old: copy_change copy_config
	cd ~/build/linux-stable && $(MAKE) olddefconfig
	cd ~/build/linux-stable && $(MAKE) menuconfig
	cd ~/build/linux-stable && sed -i -e "s/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor\"/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,provenance\"/g" .config


config_circle: copy_change
	cd ~/build/linux-stable && $(MAKE) olddefconfig
	cd ~/build/linux-stable && sed -i -e "s/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor\"/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,provenance\"/g" .config
	cd ~/build/linux-stable && sed -i -e "s/CONFIG_DEBUG_INFO=y/CONFIG_DEBUG_INFO=n/g" .config
	cd ~/build/linux-stable && sed -i -e "s/CONFIG_DEBUG_INFO_BTF=y/CONFIG_DEBUG_INFO_BTF=n/g" .config

config_circle_clang: copy_change
	cd ~/build/linux-stable && $(MAKE) olddefconfig CC=clang HOSTCC=clang
	cd ~/build/linux-stable && sed -i -e "s/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor\"/CONFIG_LSM=\"yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,provenance\"/g" .config
	cd ~/build/linux-stable && sed -i -e "s/CONFIG_DEBUG_INFO=y/CONFIG_DEBUG_INFO=n/g" .config
	cd ~/build/linux-stable && sed -i -e "s/CONFIG_DEBUG_INFO_BTF=y/CONFIG_DEBUG_INFO_BTF=n/g" .config

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
	ruby ./scripts/update_commit.rb

remove_commit:
	ruby ./scripts/remove_commit.rb

compile: update_commit compile_security compile_kernel compile_us doc remove_commit

compile_clang: update_commit compile_security_clang compile_kernel_clang compile_us_clang doc remove_commit

compile_security_only:
	cd ~/build/linux-stable && $(MAKE) security W=1

compile_security_only_clang:
	cd ~/build/linux-stable && $(MAKE) security W=1 CC=clang HOSTCC=clang

compile_security: copy_change compile_security_only doc

compile_security_clang: copy_change compile_security_only_clang doc

compile_kernel: copy_change
	cd ~/build/linux-stable && $(MAKE) -j16

compile_kernel_clang: copy_change
	cd ~/build/linux-stable && $(MAKE) -j16 CC=clang HOSTCC=clang

compile_us:
	cd ~/build/linux-stable && sudo $(MAKE) headers_install ARCH=${arch} INSTALL_HDR_PATH=/usr
	cd us-dependencies/libprovenance && $(MAKE) all

compile_us_clang:
	cd ~/build/linux-stable && sudo $(MAKE) headers_install ARCH=${arch} INSTALL_HDR_PATH=/usr CC=clang HOSTCC=clang
	cd us-dependencies/libprovenance && $(MAKE) all

config_cross_pi: copy_change
	cd ~/build/linux-stable && KERNEL=kernel7l
	cd ~/build/linux-stable && make ARCH=arm CROSS_COMPILE=/usr/bin/arm-linux-gnu- menuconfig

compile_cross_pi:
	make -j 16 ARCH=arm CROSS_COMPILE=/usr/bin/arm-linux-gnu-
	make -j 16 ARCH=arm CROSS_COMPILE=/usr/bin/arm-linux-gnu- modules

install: install_kernel install_header install_us

install_clang: install_kernel_clang install_header_clang install_us

install_header:
	cd ~/build/linux-stable && sudo $(MAKE) headers_install ARCH=${arch} INSTALL_HDR_PATH=/usr

install_header_clang:
	cd ~/build/linux-stable && sudo $(MAKE) headers_install ARCH=${arch} INSTALL_HDR_PATH=/usr CC=clang HOSTCC=clang

install_kernel:
	cd ~/build/linux-stable && sudo $(MAKE) modules_install
	cd ~/build/linux-stable && sudo $(MAKE) install
	cd ~/build/linux-stable && sudo cp -f .config /boot/config-$(kernel-version)camflow$(lsm-version)+

install_kernel_clang:
	cd ~/build/linux-stable && sudo $(MAKE) modules_install CC=clang HOSTCC=clang
	cd ~/build/linux-stable && sudo $(MAKE) install CC=clang HOSTCC=clang
	cd ~/build/linux-stable && sudo cp -f .config /boot/config-$(kernel-version)camflow$(lsm-version)+

install_us:
	cd us-dependencies/libprovenance && $(MAKE) install
	cd us-dependencies/camconfd && $(MAKE) all
	cd us-dependencies/camconfd && $(MAKE) install
	cd us-dependencies/camflowd && $(MAKE) all
	cd us-dependencies/camflowd && $(MAKE) install
	cd us-dependencies/camflow-cli && $(MAKE) all
	cd us-dependencies/camflow-cli && $(MAKE) install

clean: clean_kernel clean_us

clean_kernel:
	cd ~/build/linux-stable && $(MAKE) clean
	cd ~/build/linux-stable && $(MAKE) mrproper

clean_us:
	cd us-dependencies/libprovenance && $(MAKE) clean
	cd us-dependencies/camconfd && $(MAKE) clean
	cd us-dependencies/camflow-cli && $(MAKE) clean
	cd us-dependencies/camflowd && $(MAKE) clean

delete_kernel:
	cd ~/build && rm -rf ./pristine
	cd ~/build && rm -rf ./linux-stable

delete_us:
	cd us-dependencies && rm -rf ./camconfd
	cd us-dependencies && rm -rf ./camflow-cli
	cd us-dependencies && rm -rf ./camflowd
	cd us-dependencies && rm -rf ./libprovenance

delete: delete_us delete_kernel

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
	uncrustify -c uncrustify.cfg --replace  security/provenance/include/provenance_utils.h
	uncrustify -c uncrustify.cfg --replace security/provenance/include/memcpy_ss.h
	uncrustify -c uncrustify.cfg --replace include/linux/provenance_query.h
	uncrustify -c uncrustify.cfg --replace include/linux/provenance_types.h
	uncrustify -c uncrustify.cfg --replace include/uapi/linux/provenance_fs.h
	uncrustify -c uncrustify.cfg --replace include/uapi/linux/provenance_types.h
	uncrustify -c uncrustify.cfg --replace include/uapi/linux/provenance.h

uncrustify_clean:
	rm ./security/provenance/*backup*~
	rm ./security/provenance/include/*backup*~
	rm ./include/linux/*backup*~
	rm ./include/uapi/linux/*backup*~

patch: copy_change
	rm -rf patches
	mkdir -p patches
	cd ~/build/pristine/linux-stable && rm -f .config
	cd ~/build/pristine/linux-stable && rm -f  config_sav
	cd ~/build/pristine/linux-stable && rm -f  certs/signing_key.pem
	cd ~/build/pristine/linux-stable && rm -f	certs/x509.genkey
	cd ~/build/pristine/linux-stable && rm -f certs/signing_key.x509
	cd ~/build/pristine/linux-stable && rm -f tools/objtool/arch/x86/insn/inat-tables.c
	cd ~/build/pristine/linux-stable && $(MAKE) clean
	cd ~/build/pristine/linux-stable && $(MAKE) mrproper
	cd ~/build && wget https://github.com/camflow/information-flow-patch/releases/download/$(kernel-version)/0001-information-flow.patch
	cd ~/build/pristine/linux-stable && git apply ../../0001-information-flow.patch
	cd ~/build/pristine/linux-stable && git add .
	cd ~/build/pristine/linux-stable && git commit -a -m 'information flow'
	cp -r security ~/build/pristine/linux-stable/.
	cp -r include ~/build/pristine/linux-stable/.
	cd ~/build/pristine/linux-stable && git add .
	cd ~/build/pristine/linux-stable && git commit -a -m 'camflow'
	cd ~/build/pristine/linux-stable && git format-patch HEAD~~ -s
	cp -f ~/build/pristine/linux-stable/*.patch patches/

save_space:
	cd ~/build/linux-stable && rm -rf .git
	cd ~/build/pristine/linux-stable && rm -rf .git

prepare_dwarves:
	mkdir -p ~/build
	cd ~/build && git clone https://github.com/acmel/dwarves
	cd ~/build/dwarves && git checkout v1.16
	cd ~/build/dwarves && mkdir build
	cd ~/build/dwarves/build && cmake -D__LIB=lib ..

install_dwarves:
	cd ~/build/dwarves/build && make install
