%define lib_blkid_major 1
%define lib_blkid %mklibname blkid %{lib_blkid_major}
%define lib_blkid_devel %mklibname blkid -d

%define lib_uuid_major 1
%define lib_uuid %mklibname uuid %{lib_uuid_major}
%define lib_uuid_devel %mklibname uuid -d

%define lib_ext2fs %mklibname ext2fs 2
%define lib_ext2fs_devel %mklibname ext2fs -d

%define lib_mount_major 1
%define lib_mount %mklibname mount %{lib_mount_major}
%define lib_mount_devel %mklibname mount -d

%define git_url git://git.kernel.org/pub/scm/utils/util-linux/util-linux.git

%define build_bootstrap 0

%if !%{build_bootstrap}
%bcond_with	uclibc
%endif

### Header
Summary:	A collection of basic system utilities
Name:		util-linux
Version:	2.21.2
Release:	2
License:	GPLv2 and GPLv2+ and BSD with advertising and Public Domain
Group:		System/Base
URL:		ftp://ftp.kernel.org/pub/linux/utils/util-linux

### Features
%define include_raw 1
### Macros
%define no_hwclock_archs s390 s390x

### Dependences
BuildRequires:	gcc
BuildRequires:	sed
%if !%{build_bootstrap}
BuildRequires:	ext2fs-devel
%endif
BuildRequires:	gettext-devel
BuildRequires:	pam-devel
BuildRequires:	ncurses-devel
BuildRequires:	ncursesw-devel
BuildRequires:	termcap-devel
BuildRequires:	slang-devel
BuildRequires:	zlib-devel
BuildRequires:	libaudit-devel
%if %{with uclibc}
BuildRequires:	uClibc-devel
%endif
BuildRequires:	libtool

### Sources
Source0:	ftp://ftp.kernel.org/pub/linux/utils/%{name}/v%(echo %{version} |cut -d. -f1-2)/%{name}-%{version}.tar.xz
# based on Fedora pam files, with pam_selinux stripped out
Source1:	util-linux-ng-login.pamd
Source2:	util-linux-ng-remote.pamd
Source3:	util-linux-ng-chsh-chfn.pamd
Source4:	util-linux-ng-60-raw.rules
Source8:	nologin.c
Source9:	nologin.8
Source10:	uuidd.init

### Obsoletes & Conflicts & Provides
# old versions of util-linux have been splited to more sub-packages
%rename		mount
%rename		losetup
Obsoletes:	util-linux-ng < 2.19
Obsoletes:	util-linux <= 2.13-0.pre7.6mdv2008.0
Provides:	util-linux = %{version}-%{release}
Provides:	util-linux-ng = %{version}-%{release}
# old versions of e2fsprogs provides blkid / uuidd
Conflicts:	e2fsprogs < 1.41.8-2mnb2

%rename		fdisk
%rename		tunelp
%rename		schedutils
%ifarch alpha %{sparc} ppc
Obsoletes:	clock < %{version}-%{release}
%endif

# setarch merge in util-linux-ng-2.13
%rename		sparc32
%rename		linux32
%rename		setarch
Requires(pre):	mktemp
# for /bin/awk
Requires(pre):	gawk
# for /usr/bin/cmp
Requires(pre):	diffutils
Requires(pre):	coreutils
Requires:	pam >= 0.66-4
Requires:	shadow-utils >= 4.0.3
Requires:	%{lib_blkid} = %{version}-%{release}
Requires:	%{lib_mount} = %{version}-%{release}
Requires:	%{lib_uuid} = %{version}-%{release}
%if %{include_raw}
Requires:	udev
%endif

# RHEL/Fedora specific mount options
Patch1:		util-linux-ng-2.15-mount-managed.patch
# add note about ATAPI IDE floppy to fdformat.8
Patch3:		util-linux-ng-2.20-fdformat-man-ide.patch
# 151635 - makeing /var/log/lastlog
Patch5:		util-linux-ng-2.13-login-lastlog.patch
# 231192 - ipcs is not printing correct values on pLinux
Patch8:		util-linux-ng-2.20-ipcs-32bit.patch
# /etc/blkid.tab --> /etc/blkid/blkid.tab
Patch11:	util-linux-ng-2.16-blkid-cachefile.patch

### Upstream patches

### Mandriva Specific patches

# misc documentation fixes for man pages
Patch111:	util-linux-2.11t-mkfsman.patch
Patch114:	util-linux-2.11t-dumboctal.patch
Patch115:	util-linux-ng-2.20-fix-ioctl.patch
Patch116:	util-linux-2.12q-autodav.patch

# crypto patches
# loop-AES patch
# reworked from http://loop-aes.sourceforge.net/updates/util-linux-ng-2.17-20100120.diff.bz2
Patch1100:	util-linux-ng-2.18-loopAES.patch
Patch1101:	util-linux-2.12q-swapon-skip-encrypted.patch
Patch1102:	util-linux-2.12-lower-LOOP_PASSWORD_MIN_LENGTH-for-AES.patch
# load cryptoloop and cypher modules when use cryptoapi
Patch1103:	util-linux-2.12a-cryptoapi-load-module.patch
Patch1104:	util-linux-ng-2.14.1-set-as-encrypted.patch

# clock program for ppc
Patch1200:	util-linux-2.10r-clock-1.1-ppc.patch
# leng options for clock-ppc
Patch1201:	util-linux-2.10s-clock-syntax-ppc.patch
# Added r & w options to chfn (lsb mandate)
Patch1202:	util-linux-2.20-chfn-lsb-usergroups.patch
# fix build on alpha with newer kernel-headers
Patch1203:	util-linux-2.11m-cmos-alpha.patch
# do not hide users option in mtab
Patch1207:	util-linux-ng-2.14.1-users.patch
# (peroyvind) fixes for sparc
Patch1212:	util-linux-ng-2.20-sparc.patch
# remove mode= from udf mounts (architecture done so that more may come)
Patch1218:	util-linux-ng-2.13-mount-remove-silly-options-in-auto.patch
# (misc) enable option -x on fsck.cramfs , bug 48224
Patch1219:	util-linux-ng-enable_fsck_cramfs.diff
# Mandrivamove patches
Patch1300:	util-linux-ng-2.18-losetup-try-LOOP_CHANGE_FD-when-loop-already-busy.patch

%description
The util-linux package contains a large variety of low-level system
utilities that are necessary for a Linux system to function.  Among
others, Util-linux-ng contains the fdisk configuration tool and the login
program.

%package -n	%{lib_blkid}
Summary:	Block device ID library
Group:		System/Libraries
License:	LGPLv2+
Conflicts:	%{lib_ext2fs} < 1.41.6-2mnb2

%description -n %{lib_blkid}
This is block device identification library, part of util-linux.

%package -n	%{lib_blkid_devel}
Summary:	Block device ID library
Group:		Development/C
License:	LGPLv2+
Requires:	%{lib_blkid} = %{version}-%{release}
Conflicts:	%{lib_ext2fs_devel} < 1.41.6-2mnb2
Provides:	libblkid-devel = %{version}-%{release}

%description -n	%{lib_blkid_devel}
This is the block device identification development library and headers,
part of util-linux.

%package -n	%{lib_uuid}
Summary:	Universally unique ID library
Group:		System/Libraries
License:	BSD
Conflicts:	%{lib_ext2fs} < 1.41.8-2mnb2

%description -n %{lib_uuid}
This is the universally unique ID library, part of e2fsprogs.

The libuuid library generates and parses 128-bit universally unique
id's (UUID's).A UUID is an identifier that is unique across both
space and time, with respect to the space of all UUIDs.  A UUID can
be used for multiple purposes, from tagging objects with an extremely
short lifetime, to reliably identifying very persistent objects
across a network.

%package -n	%{lib_uuid_devel}
Summary:	Universally unique ID library
Group:		Development/C
License:	BSD
Conflicts:	%{lib_ext2fs} < 1.41.8-2mnb2
Requires:	%{lib_uuid} = %{version}
Provides:	libuuid-devel = %{version}-%{release}

%description -n %{lib_uuid_devel}
This is the universally unique ID development library and headers,
part of e2fsprogs.

The libuuid library generates and parses 128-bit universally unique
id's (UUID's).A UUID is an identifier that is unique across both
space and time, with respect to the space of all UUIDs.  A UUID can
be used for multiple purposes, from tagging objects with an extremely
short lifetime, to reliably identifying very persistent objects
across a network.

%package -n	uuidd
Summary:	Helper daemon to guarantee uniqueness of time-based UUIDs
Group:		System/Servers
License:	GPLv2
Requires(pre):	shadow-utils

%description -n	uuidd
The uuidd package contains a userspace daemon (uuidd) which guarantees
uniqueness of time-based UUID generation even at very high rates on
SMP systems.

%package -n	%{lib_mount}
Summary:	Universal mount library
Group:		System/Libraries
License:	LGPL2+

%description -n	%{lib_mount}
The libmount library is used to parse /etc/fstab,
/etc/mtab and /proc/self/mountinfo files,
manage the mtab file, evaluate mount options, etc.

%package -n	%{lib_mount_devel}
Summary:	Universally unique ID library
Group:		Development/C
License:	LGPL2+
Requires:	%{lib_mount} = %{version}-%{release}
Provides:	libmount-devel = %{version}-%{release}

%description -n	%{lib_mount_devel}
Development files and headers for libmount library.

%prep
%setup -q
cp %{SOURCE8} %{SOURCE9} .

%patch1 -p1 -b .options
%patch3 -p1 -b .atapifloppy
%patch5 -p1 -b .lastlog
%patch8 -p1 -b .p8

# Mandriva
%ifarch ppc
%patch1200 -p0
%patch1201 -p1
%endif

#LSB (sb)
%patch1202 -p1 -b .chfnlsb

#fix build on alpha with newer kernel-headers
%ifarch alpha
%patch1203 -p1
%endif

%patch111 -p1 -b .mkfsman
%patch114 -p0 -b .dumboctal
%patch115 -p1 -b .fix-ioctl
%patch116 -p1 -b .autodav

#%patch1100 -p1 -b .loopAES
#%patch1101 -p0 -b .swapon-encrypted
#%patch1102 -p0 -b .loopAES-password
#%patch1103 -p0 -b .load-module
#%patch1104 -p1 -b .set-as-encrypted

#%patch1300 -p1 -b .CHANGE-FD

%patch1207 -p1 -b .users
%patch1212 -p1 -b .sparc
%patch1218 -p1 -b .silly
%patch1219 -p0

# rebuild build system for loop-AES patch
#./autogen.sh

%build
%serverbuild
unset LINGUAS || :

# CFLAGS
%define make_cflags -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -fno-strict-aliasing

export CONFIGURE_TOP="`pwd`"

%if %{with uclibc}
mkdir -p uclibc
pushd uclibc
%configure2_5x	CC="%{uclibc_cc}" \
		CFLAGS="%{uclibc_cflags} %{make_cflags}" \
		--enable-shared=no \
		--enable-static=yes \
		--without-ncurses

%make -C libblkid
popd
%endif

mkdir -p system
pushd  system
export CFLAGS="%{make_cflags} %{optflags} -Os"
%configure2_5x \
	--bindir=/bin \
	--sbindir=/sbin \
	--libdir=/%{_lib} \
	--disable-wall \
	--enable-partx \
	--enable-login-utils \
	--enable-kill \
	--enable-write \
	--enable-arch \
	--enable-ddate \
	--disable-mountpoint \
%if %{include_raw}
	--enable-raw \
%endif
	--disable-makeinstall-chown \
	--disable-rpath \
	--with-audit

# build util-linux
%make

popd

# build nologin
gcc %{optflags} %{ldflags} -o nologin nologin.c

%ifarch ppc
gcc clock-ppc.c %{ldflags} -o clock-ppc
%endif

%install
mkdir -p %{buildroot}/{bin,sbin}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_infodir}
mkdir -p %{buildroot}%{_mandir}/man{1,6,8,5}
mkdir -p %{buildroot}%{_sbindir}
mkdir -p %{buildroot}%{_sysconfdir}/{pam.d,security/console.apps,blkid}

%if %{with uclibc}
for lib in `find uclibc -name libblkid.a -o -name libuuid.a`; do
	install -m644 $lib -D %{buildroot}%{uclibc_root}%{_libdir}/$(basename $lib)
done
%endif

# install util-linux
%makeinstall_std -C system install DESTDIR=%{buildroot} MANDIR=%{buildroot}/%{_mandir} INFODIR=%{buildroot}/%{_infodir}

# install nologin
install -m 755 nologin %{buildroot}/sbin
install -m 644 nologin.8 %{buildroot}%{_mandir}/man8

%if %{include_raw}
echo '.so man8/raw.8' > %{buildroot}%{_mandir}/man8/rawdevices.8
{
  # see RH bugzilla #216664
  mkdir -p %{buildroot}%{_sysconfdir}/udev/rules.d
  pushd %{buildroot}%{_sysconfdir}/udev/rules.d
  install -m 644 %{SOURCE4} ./60-raw.rules
  popd
}
%endif

# Correct mail spool path.
perl -pi -e 's,/usr/spool/mail,/var/spool/mail,' %{buildroot}%{_mandir}/man1/login.1

%ifarch %{sparcx}
rm -rf %{buildroot}%{_bindir}/sunhostid
cat << E-O-F > %{buildroot}%{_bindir}/sunhostid
#!/bin/sh
# this should be %{_bindir}/sunhostid or somesuch.
# Copyright 1999 Peter Jones, <pjones@redhat.com> .
# GPL and all that good stuff apply.
(
idprom=\`cat /proc/openprom/idprom\`
echo \$idprom|dd bs=1 skip=2 count=2
echo \$idprom|dd bs=1 skip=27 count=6
echo
) 2>/dev/null
E-O-F
chmod 755 %{buildroot}%{_bindir}/sunhostid
%endif

# PAM settings
{
  pushd %{buildroot}%{_sysconfdir}/pam.d
  install -m 644 %{SOURCE1} ./login
  install -m 644 %{SOURCE2} ./remote
  install -m 644 %{SOURCE3} ./chsh
  install -m 644 %{SOURCE3} ./chfn
  popd
}

# This has dependencies on stuff in /usr
mv %{buildroot}{/sbin/,/usr/sbin}/cfdisk

%ifarch ppc
cp -f ./clock-ppc %{buildroot}/sbin/clock-ppc
mv %{buildroot}/sbin/hwclock %{buildroot}/sbin/clock-rs6k
ln -sf clock-rs6k %{buildroot}/sbin/hwclock
%endif
ln -sf ../../sbin/hwclock %{buildroot}/usr/sbin/hwclock
ln -sf ../../sbin/clock %{buildroot}/usr/sbin/clock
ln -sf hwclock %{buildroot}/sbin/clock

# Our own initscript for uuidd
install -D -m 755 %{SOURCE10} %{buildroot}/etc/rc.d/init.d/uuidd
# And a dirs uuidd needs that the makefiles don't create
install -d %{buildroot}/var/run/uuidd
install -d %{buildroot}/var/lib/libuuid

# move flock in /bin, required for udev
# logger is useful in initscripts while /usr isn't mounted as well
# ionice needed for readahead_early
for p in flock logger ionice; do
	mv %{buildroot}{%{_bindir},/bin}/$p
	ln -sf ../../bin/$p %{buildroot}%{_bindir}/$p
done

# remove stuff we don't want
rm -f %{buildroot}%{_mandir}/man1/{line,newgrp,pg}.1*
rm -f %{buildroot}%{_bindir}/{line,newgrp,pg}

# Final cleanup
%ifarch %no_hwclock_archs
rm -f %{buildroot}/sbin/{hwclock,clock} %{buildroot}%{_mandir}/man8/hwclock.8* %{buildroot}/usr/sbin/{hwclock,clock}
%endif
%ifarch s390 s390x
rm -f %{buildroot}/usr/{bin,sbin}/{fdformat,tunelp,floppy} %{buildroot}%{_mandir}/man8/{fdformat,tunelp,floppy}.8*
%endif

# deprecated commands
for I in /sbin/mkfs.bfs \
	/usr/bin/chkdupexe \
	%{_bindir}/scriptreplay
	do
	rm -f %{buildroot}$I
done

# deprecated man pages
for I in man1/chkdupexe.1 \
	man8/mkfs.bfs.8 man1/scriptreplay.1; do
	rm -rf %{buildroot}%{_mandir}/${I}*
done

# we install getopt/getopt-*.{bash,tcsh} as doc files
# note: versions <=2.12 use path "%{_datadir}/misc/getopt/*"
chmod 644 getopt/getopt-*.{bash,tcsh}
rm -f %{buildroot}%{_datadir}/getopt/*
rmdir %{buildroot}%{_datadir}/getopt

# link mtab 
ln -sf /proc/mounts %{buildroot}/etc/mtab

# /usr/sbin -> /sbin
for I in addpart delpart partx; do
	if [ -e %{buildroot}/usr/sbin/$I ]; then
		mv %{buildroot}/usr/sbin/$I %{buildroot}/sbin/$I
	fi
done

# /usr/bin -> /bin
for I in taskset; do
	if [ -e %{buildroot}/usr/bin/$I ]; then
		mv %{buildroot}/usr/bin/$I %{buildroot}/bin/$I
	fi
done

# /sbin -> /bin
for I in raw; do
	if [ -e %{buildroot}/sbin/$I ]; then
		mv %{buildroot}/sbin/$I %{buildroot}/bin/$I
	fi
done

# remove vipw and vigr, they belong in shadow-utils
rm -f %{buildroot}%{_sbindir}/{vipw,vigr} %{buildroot}%{_mandir}/man8/{vigr,vipw}.*

%find_lang %{name} %{name}.lang

# the files section supports only one -f option...
mv %{name}.lang %{name}.files

# create list of setarch(8) symlinks
find  %{buildroot}%{_bindir}/ -regextype posix-egrep -type l \
	-regex ".*(linux32|linux64|s390|s390x|i386|ppc|ppc64|ppc32|sparc|sparc64|sparc32|sparc32bash|mips|mips64|mips32|ia64|x86_64)$" \
	-printf "%{_bindir}/%f\n" >> %{name}.files

find  %{buildroot}%{_mandir}/man8 -regextype posix-egrep  \
	-regex ".*(linux32|linux64|s390|s390x|i386|ppc|ppc64|ppc32|sparc|sparc64|sparc32|sparc32bash|mips|mips64|mips32|ia64|x86_64)\.8.*" \
	-printf "%{_mandir}/man8/%f*\n" >> %{name}.files

%post
%ifarch ppc
ISCHRP=`grep CHRP /proc/cpuinfo`
if [ -z "$ISCHRP" ]; then
  ln -sf /sbin/clock-ppc /sbin/hwclock
fi
%endif

%preun

%post -n %{lib_blkid}
[ -e /etc/blkid.tab ] && mv /etc/blkid.tab /etc/blkid/blkid.tab || :
[ -e /etc/blkid.tab.old ] && mv /etc/blkid.tab.old /etc/blkid/blkid.tab.old || :
rm -f /etc/mtab
ln -sf /proc/mounts /etc/mtab

%pre -n uuidd
%_pre_useradd uuidd /var/lib/libuuid /bin/false
%_pre_groupadd uuidd uuidd

%preun -n uuidd
%_preun_service uuidd

%files -f %{name}.files
%doc NEWS AUTHORS
%doc getopt/getopt-*.{bash,tcsh}
/bin/arch
/bin/dmesg
%attr(755,root,root)	/bin/login
/bin/lsblk
/bin/more
/bin/kill
/bin/taskset
/bin/ionice
/bin/findmnt
%if %{include_raw}
/bin/raw
%config %{_sysconfdir}/udev/rules.d/60-raw.rules
%endif
%config(noreplace) %{_sysconfdir}/pam.d/chfn
%config(noreplace) %{_sysconfdir}/pam.d/chsh
%config(noreplace) %{_sysconfdir}/pam.d/login
%config(noreplace) %{_sysconfdir}/pam.d/remote
%ghost %verify(not md5 size mtime) %config(noreplace,missingok) /etc/mtab
/sbin/agetty
%{_mandir}/man8/agetty.8*
/sbin/blkid
/sbin/blockdev
/sbin/fstrim
/sbin/pivot_root
/sbin/ctrlaltdel
/sbin/addpart
/sbin/delpart
/sbin/partx
/sbin/fsfreeze
/sbin/swaplabel
%{_mandir}/man8/partx.8*
%{_mandir}/man8/addpart.8*
%{_mandir}/man8/delpart.8*
%{_mandir}/man8/findmnt.8*
%{_mandir}/man8/fsfreeze.8*
%{_mandir}/man8/fstrim.8*
%{_mandir}/man8/lsblk.8*
%{_mandir}/man8/swaplabel.8*
%ifarch %ix86 alpha ia64 x86_64 s390 s390x ppc ppc64 %{sparcx} %mips %arm
/sbin/sfdisk
%{_mandir}/man8/sfdisk.8*
%{_sbindir}/cfdisk
%{_mandir}/man8/cfdisk.8*
%endif
/sbin/fdisk
%{_mandir}/man8/fdisk.8*
%ifnarch %no_hwclock_archs
/sbin/clock
%{_sbindir}/clock
/sbin/hwclock
/usr/sbin/hwclock
%{_mandir}/man8/hwclock.8*
%endif
%ifarch ppc
/sbin/clock-ppc
/sbin/clock-rs6k
%endif
/sbin/findfs
/sbin/fsck
/sbin/mkfs
/sbin/mkswap
/sbin/nologin
%{_mandir}/man8/nologin.8*
%{_bindir}/chrt
%{_bindir}/ionice
%{_bindir}/cal
%attr(4711,root,root)	%{_bindir}/chfn
%attr(4711,root,root)	%{_bindir}/chsh
%{_bindir}/col
%{_bindir}/colcrt
%{_bindir}/colrm
%{_bindir}/column
%ifarch %ix86 alpha ppc ppc64 %{sparcx} x86_64 %mips %arm
%{_bindir}/cytune
%{_mandir}/man8/cytune.8*
%endif
%{_bindir}/ddate
%ifnarch s390 s390x
%{_sbindir}/fdformat
%endif
/bin/flock
%{_bindir}/flock
%{_bindir}/fallocate
%{_bindir}/getopt
%{_bindir}/hexdump
%{_bindir}/ipcrm
%{_bindir}/ipcs
%{_bindir}/isosize
/bin/logger
%{_bindir}/logger
%{_bindir}/look
%{_bindir}/mcookie
%ifarch %ix86 alpha ia64 x86_64 s390 s390x ppc ppc64 %{sparcx} %mips %arm
/sbin/fsck.cramfs
/sbin/mkfs.cramfs
%endif
/sbin/fsck.minix
/sbin/mkfs.minix
/sbin/chcpu
%{_bindir}/namei
%_bindir/prlimit
%{_bindir}/rename
%{_bindir}/renice
%{_bindir}/rev
%{_bindir}/script
%{_bindir}/setarch
%{_bindir}/setsid
%{_bindir}/setterm
%ifarch %{sparcx}
%{_bindir}/sunhostid
%endif
%{_bindir}/tailf
%{_bindir}/ul
%{_bindir}/unshare
%{_bindir}/uuidgen
%{_bindir}/whereis
%{_bindir}/ipcmk
%{_bindir}/lscpu
%attr(2755,root,tty)	%{_bindir}/write
%{_sbindir}/readprofile
%ifnarch s390 s390x
%{_sbindir}/tunelp
%endif
%{_sbindir}/rtcwake
%{_sbindir}/ldattach
%{_mandir}/man1/arch.1*
%{_mandir}/man1/cal.1*
%_mandir/man8/chcpu.8*
%{_mandir}/man1/chfn.1*
%{_mandir}/man1/chsh.1*
%{_mandir}/man1/col.1*
%{_mandir}/man1/colcrt.1*
%{_mandir}/man1/colrm.1*
%{_mandir}/man1/column.1*
%{_mandir}/man1/ddate.1*
%{_mandir}/man1/flock.1*
%{_mandir}/man1/fallocate.1*
%{_mandir}/man1/getopt.1*
%{_mandir}/man1/hexdump.1*
%{_mandir}/man1/kill.1*
%{_mandir}/man1/logger.1*
%{_mandir}/man1/login.1*
%{_mandir}/man1/look.1*
%{_mandir}/man1/mcookie.1*
%{_mandir}/man1/more.1*
%{_mandir}/man1/namei.1*
%_mandir/man1/prlimit.1*
%{_mandir}/man1/rename.1*
%{_mandir}/man1/rev.1*
%{_mandir}/man1/script.1*
%{_mandir}/man1/setterm.1*
%{_mandir}/man1/tailf.1*
%{_mandir}/man1/ul.1*
%{_mandir}/man1/uuidgen.1*
%{_mandir}/man1/unshare.1*
%{_mandir}/man1/whereis.1*
%{_mandir}/man1/write.1*
%{_mandir}/man1/chrt.1*
%{_mandir}/man1/ionice.1*
%{_mandir}/man1/taskset.1*
%{_mandir}/man1/renice.1*
%{_mandir}/man1/ipcrm.1*
%{_mandir}/man1/ipcs.1*
%{_mandir}/man1/setsid.1*
%{_mandir}/man1/dmesg.1*
%{_mandir}/man1/ipcmk.1*
%{_mandir}/man1/lscpu.1*
%{_mandir}/man3/uuid_generate_time_safe.3*
%{_mandir}/man8/blockdev.8*
%{_mandir}/man8/blkid.8*
%{_mandir}/man8/ctrlaltdel.8*
%ifnarch s390 s390x
%{_mandir}/man8/fdformat.8*
%endif
%{_mandir}/man8/findfs.8*
%{_mandir}/man8/fsck.8*
%{_mandir}/man8/isosize.8*
%{_mandir}/man8/mkfs.8*
%{_mandir}/man8/mkswap.8*
%{_mandir}/man8/pivot_root.8*
%if %{include_raw}
%{_mandir}/man8/raw.8*
%{_mandir}/man8/rawdevices.8*
%endif
%_mandir/man8/readprofile.8*
%ifnarch s390 s390x
%{_mandir}/man8/tunelp.8*
%endif
%{_mandir}/man8/setarch.8*
%{_mandir}/man8/rtcwake.8*
%{_mandir}/man8/ldattach.8*
%{_mandir}/man8/wipefs.8*
%{_mandir}/man8/fsck.minix.8*
%{_mandir}/man8/mkfs.minix.8*
%attr(4755,root,root)	/bin/mount
%attr(4755,root,root)	/bin/umount
/sbin/swapon
/sbin/swapoff
/sbin/switch_root
%{_mandir}/man5/fstab.5*
%{_mandir}/man8/mount.8*
%{_mandir}/man8/swapoff.8*
%{_mandir}/man8/swapon.8*
%{_mandir}/man8/switch_root.8*
%{_mandir}/man8/umount.8*
%{_mandir}/man8/losetup.8*
%lang(ru)	%{_mandir}/ru/man1/ddate.1*
/sbin/losetup
/sbin/wipefs

%files -n uuidd
%{_initrddir}/uuidd
%{_mandir}/man8/uuidd.8*
%attr(-, uuidd, uuidd) %{_sbindir}/uuidd
%dir %attr(2775, uuidd, uuidd) /var/lib/libuuid
%dir %attr(2775, uuidd, uuidd) /var/run/uuidd

%files -n %{lib_blkid}
%dir /etc/blkid
/%{_lib}/libblkid.so.%{lib_blkid_major}*

%files -n %{lib_blkid_devel}
%{_libdir}/libblkid.a
%if %{with uclibc}
%{uclibc_root}%{_libdir}/libblkid.a
%endif
%{_libdir}/libblkid.so
%{_includedir}/blkid
%{_mandir}/man3/libblkid.3*
%{_libdir}/pkgconfig/blkid.pc

%files -n %{lib_uuid}
/%{_lib}/libuuid.so.%{lib_uuid_major}*

%files -n %{lib_uuid_devel}
%{_libdir}/libuuid.a
%if %{with uclibc}
%{uclibc_root}%{_libdir}/libuuid.a
%endif
%{_libdir}/libuuid.so
%{_includedir}/uuid
%{_mandir}/man3/uuid.3*
%{_mandir}/man3/uuid_clear.3*
%{_mandir}/man3/uuid_compare.3*
%{_mandir}/man3/uuid_copy.3*
%{_mandir}/man3/uuid_generate.3*
%{_mandir}/man3/uuid_generate_random.3*
%{_mandir}/man3/uuid_generate_time.3*
%{_mandir}/man3/uuid_is_null.3*
%{_mandir}/man3/uuid_parse.3*
%{_mandir}/man3/uuid_time.3*
%{_mandir}/man3/uuid_unparse.3*
%{_libdir}/pkgconfig/uuid.pc

%files -n %{lib_mount}
/%{_lib}/libmount.so.%{lib_mount_major}*

%files -n %{lib_mount_devel}
%{_includedir}/libmount/libmount.h
%{_libdir}/libmount.so
%{_libdir}/libmount.*a
%{_libdir}/pkgconfig/mount.pc
