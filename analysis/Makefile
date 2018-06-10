prepare: prepare_gcc prepare_gpp prepare_m4 prepare_callgraph

prepare_gcc:
	wget http://mirrors.kernel.org/ubuntu/pool/universe/g/gcc-4.8/gcc-4.8-base_4.8.5-4ubuntu2_amd64.deb
	sudo dpkg -i gcc-4.8-base_4.8.5-4ubuntu2_amd64.deb
	wget http://mirrors.kernel.org/ubuntu/pool/universe/g/gcc-4.8/libasan0_4.8.5-4ubuntu2_amd64.deb
	sudo dpkg -i libasan0_4.8.5-4ubuntu2_amd64.deb
	wget http://mirrors.kernel.org/ubuntu/pool/universe/c/cloog/libcloog-isl4_0.18.4-1_amd64.deb
	sudo dpkg -i libcloog-isl4_0.18.4-1_amd64.deb
	wget http://mirrors.kernel.org/ubuntu/pool/universe/g/gcc-4.8/cpp-4.8_4.8.5-4ubuntu2_amd64.deb
	sudo dpkg -i cpp-4.8_4.8.5-4ubuntu2_amd64.deb
	wget http://mirrors.kernel.org/ubuntu/pool/universe/g/gcc-4.8/libgcc-4.8-dev_4.8.5-4ubuntu2_amd64.deb
	sudo dpkg -i libgcc-4.8-dev_4.8.5-4ubuntu2_amd64.deb
	wget http://mirrors.kernel.org/ubuntu/pool/universe/g/gcc-4.8/libstdc++-4.8-dev_4.8.5-4ubuntu2_amd64.deb
	sudo dpkg -i libstdc++-4.8-dev_4.8.5-4ubuntu2_amd64.deb
	wget http://mirrors.kernel.org/ubuntu/pool/universe/g/gcc-4.8/gcc-4.8_4.8.5-4ubuntu2_amd64.deb
	sudo dpkg -i gcc-4.8_4.8.5-4ubuntu2_amd64.deb
	wget http://mirrors.kernel.org/ubuntu/pool/universe/g/gcc-4.8/g++-4.8_4.8.5-4ubuntu2_amd64.deb
	sudo dpkg -i g++-4.8_4.8.5-4ubuntu2_amd64.deb
	wget http://mirrors.kernel.org/ubuntu/pool/main/g/gmp/libgmpxx4ldbl_6.1.0+dfsg-2_amd64.deb
	sudo dpkg -i libgmpxx4ldbl_6.1.0+dfsg-2_amd64.deb
	wget http://mirrors.kernel.org/ubuntu/pool/main/g/gmp/libgmp-dev_6.1.0+dfsg-2_amd64.deb
	sudo dpkg -i libgmp-dev_6.1.0+dfsg-2_amd64.deb
	wget http://mirrors.kernel.org/ubuntu/pool/universe/g/gcc-4.8/gcc-4.8-plugin-dev_4.8.5-4ubuntu2_amd64.deb
	sudo dpkg -i gcc-4.8-plugin-dev_4.8.5-4ubuntu2_amd64.deb
	sudo apt-get -f install -y
	rm *.deb
	sudo rm /usr/bin/gcc
	sudo ln -s /usr/bin/gcc-4.8 /usr/bin/gcc

prepare_gpp:
	sudo rm /usr/bin/g++
	sudo ln -s /usr/bin/g++-4.8 /usr/bin/g++

prepare_m4:
	sudo mv ../scripts/m4/* /usr/share/aclocal

prepare_callgraph:
	mkdir -p ../build
	cd ../build && git clone https://github.com/CamFlow/callgraphs.git

config: config_callgraph config_kernel config_sqlite

config_callgraph:
	cd ../build/callgraphs && ls
	cd ../build/callgraphs && autoreconf --install -vv
	cd ../build/callgraphs && ./configure
	cd ../build/callgraphs && $(MAKE)
	cd ../build/callgraphs && sudo $(MAKE) install

config_kernel:
	cp -f ./.config ../build/linux-stable/
	cd .. && $(MAKE) config_circle
	cd ../build/linux-stable && sed -i "s/CONFIG_CC_STACKPROTECTOR_STRONG=y/CONFIG_CC_STACKPROTECTOR_STRONG=n/" .config

config_sqlite:
	cd ../build/linux-stable && touch create_db.sh
	cd ../build/linux-stable && echo '#!/bin/bash' >> create_db.sh
	cd ../build/linux-stable && echo 'cat <<EOF | sqlite3 db.sqlite' >> create_db.sh
	cd ../build/linux-stable && echo 'CREATE TABLE functions (Id INTEGER PRIMARY KEY, Name TEXT, File TEXT, Line INTEGER, Global INTEGER);' >> create_db.sh
	cd ../build/linux-stable && echo 'CREATE TABLE calls (Caller INTEGER, Callee INTEGER, PRIMARY KEY (Caller,Callee));' >> create_db.sh
	cd ../build/linux-stable && echo 'EOF' >> create_db.sh
	cd ../build/linux-stable && chmod u+x create_db.sh
	cd ../build/linux-stable && ./create_db.sh

compile:
	cd ../build/linux-stable && $(MAKE) CC=gcc HOSTCC=gcc EXTRA_CFLAGS="-fplugin=kayrebt_callgraphs -fplugin-arg-kayrebt_callgraphs-dbfile=db.sqlite"

run: run_analysis

run_analysis:
	cd ../scripts && python syscall.py /root/circulate/build/linux-stable/db.sqlite syscalls.txt syslist.txt
	cd ../scripts && python analyze.py /root/circulate/build/linux-stable/db.sqlite syslist.txt syshooks.txt
	cd ../scripts && python stats.py syshooks.txt stats.txt

run_local:
	cd ../scripts && python syscall.py ../build/linux-stable/db.sqlite syscalls.txt syslist.txt
	cd ../scripts && python analyze.py ../build/linux-stable/db.sqlite syslist.txt syshooks.txt
	cd ../scripts && python stats.py syshooks.txt ../docs/STATS.md
