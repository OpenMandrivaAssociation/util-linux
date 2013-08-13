%define blkid_major 1
%define libblkid %mklibname blkid %{blkid_major}
%define devblkid %mklibname blkid -d

%define uuid_major 1
%define libuuid %mklibname uuid %{uuid_major}
%define devuuid %mklibname uuid -d

%define libext2fs %mklibname ext2fs 2
%define devext2fs %mklibname ext2fs -d

%define	mount_major 1
%define	libmount %mklibname mount %{mount_major}
%define	devmount %mklibname mount -d

%define git_url git://git.kernel.org/pub/scm/utils/util-linux/util-linux.git

%define build_bootstrap 0
### Features
%define include_raw 1
### Macros
%define no_hwclock_archs s390 s390x

%if !%{build_bootstrap}
%bcond_without uclibc
%endif

Summary:	A collection of basic system utilities
Name:		util-linux
Version:	2.23.2
Release:	2
License:	GPLv2 and GPLv2+ and BSD with advertising and Public Domain
Group:		System/Base
URL:		ftp://ftp.kernel.org/pub/linux/utils/util-linux
Source0:	ftp://ftp.kernel.org/pub/linux/utils/%{name}/v%(echo %{version} |cut -d. -f1-2)/%{name}-%{version}.tar.xz
# based on Fedora pam files, with pam_selinux stripped out
Source1:	util-linux-login.pamd
Source2:	util-linux-remote.pamd
Source3:	util-linux-chsh-chfn.pamd
Source4:	util-linux-60-raw.rules
Source5:	util-linux-su.pamd
Source6:	util-linux-su-l.pamd
Source7:	util-linux-runuser.pamd
Source8:	util-linux-runuser-l.pamd
Source9:	nologin.c
Source10:	nologin.8
Source11:	uuidd-tmpfiles.conf
# RHEL/Fedora specific mount options
Patch1:		util-linux-2.23.1-mount-managed.patch
# add note about ATAPI IDE floppy to fdformat.8
Patch3:		util-linux-ng-2.20-fdformat-man-ide.patch
# 151635 - makeing /var/log/lastlog
Patch5:		util-linux-ng-2.13-login-lastlog.patch
# /etc/blkid.tab --> /etc/blkid/blkid.tab
Patch11:	util-linux-ng-2.16-blkid-cachefile.patch
Patch12:	util-linux-2.23.1-mkstemp.patch
### Upstream patches

### Mandriva Specific patches

# misc documentation fixes for man pages
Patch111:	util-linux-2.11t-mkfsman.patch
# sparc build fix
Patch115:	util-linux-2.22-fix-ioctl.patch
# Autodetect davfs mount attempts
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
# remove mode= from udf mounts (architecture done so that more may come)
Patch1218:	util-linux-ng-2.13-mount-remove-silly-options-in-auto.patch
# (misc) enable option -x on fsck.cramfs , bug 48224
Patch1219:	util-linux-ng-enable_fsck_cramfs.diff
# Mandrivamove patches
Patch1300:	util-linux-ng-2.18-losetup-try-LOOP_CHANGE_FD-when-loop-already-busy.patch

BuildRequires:	gcc
BuildRequires:	libtool
BuildRequires:	sed
BuildRequires:	rpm-build >= 1:5.4.10-5
BuildRequires:	audit-devel
BuildRequires:	gettext-devel
BuildRequires:	pam-devel
%if %{with uclibc}
BuildRequires:	uClibc-devel >= 0.9.33.2-16
%endif
%if !%{build_bootstrap}
BuildRequires:	pkgconfig(ext2fs)
%endif
BuildRequires:	pkgconfig(ncursesw) >= 5.9-6.20120922.3
#BuildRequires:	termcap-devel
BuildRequires:	pkgconfig(slang)
BuildRequires:	pkgconfig(systemd)
BuildRequires:	pkgconfig(zlib)
BuildRequires:	pkgconfig(libcap-ng)

Provides:	/bin/su
%rename		eject
%rename		fdisk
%rename		linux32
%rename		losetup
%rename		mount
%rename		tunelp
%rename		sparc32
%rename		schedutils
%rename		setarch
%rename		util-linux-ng
%ifarch alpha %{sparc} ppc
Obsoletes:	clock < %{version}-%{release}
%endif
# old versions of e2fsprogs provides blkid / uuidd
Conflicts:	e2fsprogs < 1.41.8-2mnb2
Conflicts:	setup < 2.7.18-6
# old version of sysvinit-tools provides sulogin and utmpdump
Conflicts:	sysvinit < 2.87-11
# (tpg) add conflicts on older version dues to move su
Conflicts:	coreutils < 8.19-2
# (proyvind): handle sulogin, wall, mountpoint being moved
Conflicts:	sysvinit-tools < 2.87-17
Conflicts:	bash-completion < 2.1-1

# for /bin/awk
Requires(pre):	gawk
# for /usr/bin/cmp
Requires(pre):	diffutils
Requires(pre):	coreutils
Requires:	pam >= 0.66-4
Requires:	shadow-utils >= 4.0.3
Requires:	%{libblkid} = %{version}-%{release}
Requires:	%{libmount} = %{version}-%{release}
Requires:	%{libuuid} = %{version}-%{release}
%if %{include_raw}
Requires:	udev
%endif

%description
The util-linux package contains a large variety of low-level system
utilities that are necessary for a Linux system to function.  Among
others, Util-linux-ng contains the fdisk configuration tool and the login
program.

%if %{with uclibc}
%package -n	uclibc-%{name}
Summary:	uClibc build of util-linux
Group:		System/Base

%description -n	uclibc-%{name}
The util-linux package contains a large variety of low-level system
utilities that are necessary for a Linux system to function.  Among
others, Util-linux-ng contains the fdisk configuration tool and the login
program.
%endif

%package -n	%{libblkid}
Summary:	Block device ID library
Group:		System/Libraries
License:	LGPLv2+
Conflicts:	%{libext2fs} < 1.41.6-2mnb2
# MD this is because of the cmd rm and ln in the post config
Requires(post):	coreutils

%description -n %{libblkid}
This is block device identification library, part of util-linux.

%if %{with uclibc}
%package -n	uclibc-%{libblkid}
Summary:	Block device ID library (uClibc linked)
Group:		System/Libraries
License:	LGPLv2+
Conflicts:	%{libext2fs} < 1.41.6-2mnb2

%description -n	uclibc-%{libblkid}
This is block device identification library, part of util-linux.
%endif

%package -n	%{devblkid}
Summary:	Block device ID library
Group:		Development/C
License:	LGPLv2+
Requires:	%{libblkid} = %{version}-%{release}
%if %{with uclibc}
Requires:	uclibc-%{libblkid} = %{version}-%{release}
%endif
Conflicts:	%{devext2fs} < 1.41.6-2mnb2
Provides:	libblkid-devel = %{version}-%{release}

%description -n	%{devblkid}
This is the block device identification development library and headers,
part of util-linux.

%package -n	%{libuuid}
Summary:	Universally unique ID library
Group:		System/Libraries
License:	BSD
Conflicts:	%{libext2fs} < 1.41.8-2mnb2

%description -n	%{libuuid}
This is the universally unique ID library, part of e2fsprogs.

The libuuid library generates and parses 128-bit universally unique
id's (UUID's).A UUID is an identifier that is unique across both
space and time, with respect to the space of all UUIDs.  A UUID can
be used for multiple purposes, from tagging objects with an extremely
short lifetime, to reliably identifying very persistent objects
across a network.

%if %{with uclibc}
%package -n	uclibc-%{libuuid}
Summary:	Universally unique ID library (uClibc linked)
Group:		System/Libraries
License:	BSD
Conflicts:	%{libext2fs} < 1.41.8-2mnb2

%description -n	uclibc-%{libuuid}
This is the universally unique ID library, part of e2fsprogs.

The libuuid library generates and parses 128-bit universally unique
id's (UUID's).A UUID is an identifier that is unique across both
space and time, with respect to the space of all UUIDs.  A UUID can
be used for multiple purposes, from tagging objects with an extremely
short lifetime, to reliably identifying very persistent objects
across a network.
%endif

%package -n	%{devuuid}
Summary:	Universally unique ID library
Group:		Development/C
License:	BSD
Conflicts:	%{libext2fs} < 1.41.8-2mnb2
Requires:	%{libuuid} = %{version}
%if %{with uclibc}
Requires:	uclibc-%{libuuid} = %{version}-%{release}
%endif
Provides:	libuuid-devel = %{version}-%{release}

%description -n	%{devuuid}
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
Requires(post):	systemd
Requires(pre):	shadow-utils
Requires(pre):	rpm-helper
Requires(post):	rpm-helper
Requires(preun):	rpm-helper
Requires(postun):	rpm-helper

%description -n	uuidd
The uuidd package contains a userspace daemon (uuidd) which guarantees
uniqueness of time-based UUID generation even at very high rates on
SMP systems.

%package -n	%{libmount}
Summary:	Universal mount library
Group:		System/Libraries
License:	LGPLv2+

%description -n	%{libmount}
The libmount library is used to parse /etc/fstab,
/etc/mtab and /proc/self/mountinfo files,
manage the mtab file, evaluate mount options, etc.

%if %{with uclibc}
%package -n	uclibc-%{libmount}
Summary:	Universal mount library (uClibc linked)
Group:		System/Libraries
License:	LGPLv2+

%description -n	uclibc-%{libmount}
The libmount library is used to parse /etc/fstab,
/etc/mtab and /proc/self/mountinfo files,
manage the mtab file, evaluate mount options, etc.
%endif

%package -n	%{devmount}
Summary:	Universally unique ID library
Group:		Development/C
License:	LGPLv2+
Requires:	%{libmount} = %{version}-%{release}
%if %{with uclibc}
Requires:	uclibc-%{libmount} = %{version}-%{release}
%endif
Provides:	libmount-devel = %{version}-%{release}

%description -n	%{devmount}
Development files and headers for libmount library.

%prep
%setup -q
cp %{SOURCE9} %{SOURCE10} .

%patch1 -p1 -b .options
%patch3 -p1 -b .atapifloppy
%patch5 -p1 -b .lastlog
%patch12 -p1 -b .mkstemp

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
%patch115 -p1 -b .fix-ioctl
#patch116 -p1 -b .autodav

#%patch1100 -p1 -b .loopAES
#%patch1101 -p0 -b .swapon-encrypted
#%patch1102 -p0 -b .loopAES-password
#%patch1103 -p0 -b .load-module
#%patch1104 -p1 -b .set-as-encrypted

#%patch1300 -p1 -b .CHANGE-FD

# FIXME: double-check if this is really obsoleted by the mount rewrite
#patch1218 -p1 -b .silly
%patch1219 -p0

# rebuild build system for loop-AES patch
./autogen.sh

%build
%global optflags %{optflags} -Os

%ifarch %{ix86}
%global ldflags %{ldflags} -fuse-ld=bfd
%endif

%serverbuild_hardened
unset LINGUAS || :

export CONFIGURE_TOP="$PWD"

%if %{with uclibc}
mkdir -p uclibc
pushd uclibc
%uclibc_configure \
		--bindir=%{uclibc_root}/bin \
		--sbindir=%{uclibc_root}/sbin \
		--prefix=%{uclibc_root} \
		--exec-prefix=%{uclibc_root} \
		--libdir=%{uclibc_root}/%{_lib} \
		--host=%{_host} \
		--enable-rpath=no \
		--enable-shared=yes \
		--enable-static=no \
		--disable-chfn-chsh \
		--enable-libuuid \
		--enable-libblkid \
		--enable-libmount \
		--disable-mount \
		--disable-losetup \
		--disable-fsck \
		--disable-partx \
		--disable-uuidd \
		--disable-mountpoint \
		--disable-fallocate \
		--disable-unshare \
		--disable-eject \
		--disable-agetty \
		--disable-cramfs \
		--disable-switch_root \
		--disable-pivot_root \
		--disable-kill \
		--disable-utmpdump \
		--disable-rename \
		--disable-login \
		--disable-sulogin \
		--disable-su \
		--disable-schedutils \
		--disable-wall \
		--disable-makeinstall-chown \
		--disable-fsck \
		--disable-raw \
		--enable-socket-activation
%make

popd
%endif

mkdir -p system
pushd  system
%configure2_5x \
	CFLAGS="%{optflags} -Os" \
	--bindir=/bin \
	--sbindir=/sbin \
	--libdir=/%{_lib} \
	--enable-wall \
	--enable-partx \
	--enable-login-utils \
	--enable-kill \
	--enable-write \
	--enable-mountpoint \
%if %{include_raw}
	--enable-raw \
%endif
	--disable-makeinstall-chown \
	--disable-rpath \
	--with-audit \
	--enable-new-mount \
	--enable-chfn-chsh \
	--enable-socket-activation \
	--enable-tunelp

# build util-linux
%make

popd

# build nologin
# plz do not use gcc, we have special macro to define compiler 
# it named %%{__cc} /usr/bin/gcc produce wrong binaries when crosscompiling
%{__cc} %{optflags} %{ldflags} -o nologin nologin.c

%ifarch ppc
%{__cc} clock-ppc.c %{ldflags} -o clock-ppc
%endif

%install
mkdir -p %{buildroot}/{bin,sbin}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_infodir}
mkdir -p %{buildroot}%{_mandir}/man{1,6,8,5}
mkdir -p %{buildroot}%{_sbindir}
mkdir -p %{buildroot}%{_sysconfdir}/{pam.d,security/console.apps,blkid}

%if %{with uclibc}
make -C uclibc install-sbinPROGRAMS install-usrlib_execLTLIBRARIES DESTDIR="%{buildroot}"
install -m755 uclibc/setterm -D %{buildroot}%{uclibc_root}%{_bindir}/setterm

mkdir -p %{buildroot}%{uclibc_root}%{_libdir}
for l in lib{blkid,mount,uuid}.so; do
	rm -f %{buildroot}%{uclibc_root}/%{_lib}/$l
	ln -sr %{buildroot}%{uclibc_root}/%{_lib}/$l.*.* %{buildroot}%{uclibc_root}%{_libdir}/$l
done
for bin in blockdev cfdisk chcpu ctrlaltdel fdisk findfs fsck.minix fsfreeze fstrim \
	hwclock mkfs mkfs.bfs mkfs.minix swapoff swapon wipefs; do
	rm -f %{buildroot}%{uclibc_root}/sbin/$bin
done
%endif

# install util-linux
%makeinstall_std -C system install DESTDIR=%{buildroot} MANDIR=%{buildroot}%{_mandir} INFODIR=%{buildroot}%{_infodir}

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
  install -m 644 %{SOURCE5} ./su
  install -m 644 %{SOURCE6} ./su-l
  install -m 644 %{SOURCE7} ./runuser
  install -m 644 %{SOURCE8} ./runuser-l
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

install -D -p -m 644 %{SOURCE11} %{buildroot}%{_sysconfdir}/tmpfiles.d/uuidd.conf

# And a dirs uuidd needs that the makefiles don't create
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
chmod 644 misc-utils/getopt-*.{bash,tcsh}
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

%ifarch ppc
%post
ISCHRP=`grep CHRP /proc/cpuinfo`
if [ -z "$ISCHRP" ]; then
  ln -sf /sbin/clock-ppc /sbin/hwclock
fi
%endif

%post -n %{libblkid}
[ -e /etc/blkid.tab ] && mv /etc/blkid.tab /etc/blkid/blkid.tab || :
[ -e /etc/blkid.tab.old ] && mv /etc/blkid.tab.old /etc/blkid/blkid.tab.old || :
rm -f /etc/mtab
ln -sf /proc/mounts /etc/mtab

%pre -n uuidd
%_pre_useradd uuidd /var/lib/libuuid /bin/false
%_pre_groupadd uuidd uuidd

%post -n uuidd
systemd-tmpfiles --create uuidd.conf
%_post_service uuidd

%preun -n uuidd
%_preun_service uuidd

%postun -n uuidd
%_postun_userdel uuidd

%files -f %{name}.files
%doc NEWS AUTHORS
%doc misc-utils/getopt-*.{bash,tcsh}
/bin/dmesg
%attr(755,root,root)	/bin/login
/bin/lsblk
/bin/more
/bin/kill
/bin/taskset
/bin/ionice
/bin/findmnt
/bin/mountpoint
%{_bindir}/nsenter
%{_bindir}/setpriv
/bin/su
%attr(2555,root,tty) %{_bindir}/wall
/bin/wdctl
%if %{include_raw}
/bin/raw
%config %{_sysconfdir}/udev/rules.d/60-raw.rules
%endif
%config(noreplace) %{_sysconfdir}/pam.d/chfn
%config(noreplace) %{_sysconfdir}/pam.d/chsh
%config(noreplace) %{_sysconfdir}/pam.d/login
%config(noreplace) %{_sysconfdir}/pam.d/remote
%config(noreplace) %{_sysconfdir}/pam.d/su
%config(noreplace) %{_sysconfdir}/pam.d/su-l
%config(noreplace) %{_sysconfdir}/pam.d/runuser
%config(noreplace) %{_sysconfdir}/pam.d/runuser-l
%ghost %verify(not md5 size mtime) %config(noreplace,missingok) /etc/mtab
/sbin/agetty
%{_mandir}/man8/agetty.8*
/sbin/blkid
/sbin/blkdiscard
/sbin/blockdev
/sbin/fstrim
/sbin/pivot_root
/sbin/ctrlaltdel
/sbin/addpart
/sbin/delpart
/sbin/partx
/sbin/fsfreeze
/sbin/swaplabel
/sbin/runuser
%{_mandir}/man8/partx.8*
%{_mandir}/man8/addpart.8*
%{_mandir}/man8/delpart.8*
%{_mandir}/man8/findmnt.8*
%{_mandir}/man8/fsfreeze.8*
%{_mandir}/man8/fstrim.8*
%{_mandir}/man8/lsblk.8*
%{_mandir}/man8/swaplabel.8*
%{_mandir}/man1/mountpoint.1*
%{_mandir}/man1/nsenter.1*
%{_mandir}/man1/setpriv.1*
%{_mandir}/man1/wall.1*
%ifarch %ix86 alpha ia64 x86_64 s390 s390x ppc ppc64 %{sparcx} %mips %arm aarch64
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
/sbin/sulogin
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
%ifarch %ix86 alpha ppc ppc64 %{sparcx} x86_64 %mips %arm aarch64
%{_bindir}/cytune
%{_mandir}/man8/cytune.8*
%endif
%{_bindir}/eject
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
%{_bindir}/lslocks
%{_bindir}/mcookie
%{_bindir}/utmpdump
%ifarch %ix86 alpha ia64 x86_64 s390 s390x ppc ppc64 %{sparcx} %mips %arm aarch64
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
%{_sbindir}/resizepart
%{_mandir}/man1/cal.1*
%{_mandir}/man8/chcpu.8*
%{_mandir}/man1/chfn.1*
%{_mandir}/man1/chsh.1*
%{_mandir}/man1/col.1*
%{_mandir}/man1/colcrt.1*
%{_mandir}/man1/colrm.1*
%{_mandir}/man1/column.1*
%{_mandir}/man1/eject.1*
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
%{_mandir}/man1/prlimit.1*
%{_mandir}/man1/rename.1*
%{_mandir}/man1/rev.1*
%{_mandir}/man1/script.1*
%{_mandir}/man1/setterm.1*
%{_mandir}/man1/tailf.1*
%{_mandir}/man1/ul.1*
%{_mandir}/man1/uuidgen.1*
%{_mandir}/man1/unshare.1*
%{_mandir}/man1/utmpdump.1*
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
%{_mandir}/man1/su.1*
%{_mandir}/man3/uuid_generate_time_safe.3*
%{_mandir}/man8/blockdev.8*
%{_mandir}/man8/blkid.8*
%{_mandir}/man8/blkdiscard.8*
%{_mandir}/man8/ctrlaltdel.8*
%ifnarch s390 s390x
%{_mandir}/man8/fdformat.8*
%endif
%{_mandir}/man8/findfs.8*
%{_mandir}/man8/fsck.8*
%{_mandir}/man8/fsck.cramfs.8*
%{_mandir}/man8/isosize.8*
%{_mandir}/man8/lslocks.8*
%{_mandir}/man8/mkfs.8*
%{_mandir}/man8/mkfs.cramfs.8*
%{_mandir}/man8/mkswap.8*
%{_mandir}/man8/pivot_root.8*
%if %{include_raw}
%{_mandir}/man8/raw.8*
%{_mandir}/man8/rawdevices.8*
%endif
%_mandir/man8/readprofile.8*
%_mandir/man8/resizepart.8*
%ifnarch s390 s390x
%{_mandir}/man8/tunelp.8*
%endif
%{_mandir}/man8/setarch.8*
%{_mandir}/man8/sulogin.8*
%{_mandir}/man8/rtcwake.8*
%{_mandir}/man8/ldattach.8*
%{_mandir}/man8/wipefs.8*
%{_mandir}/man8/wdctl.8*
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
%{_mandir}/man1/runuser.1*
%{_mandir}/man8/umount.8*
%{_mandir}/man8/losetup.8*
/sbin/losetup
/sbin/wipefs
%{_datadir}/bash-completion/completions/*

%if %{with uclibc}
%files -n uclibc-%{name}
%{uclibc_root}/sbin/blkdiscard
%{uclibc_root}/sbin/runuser
%{uclibc_root}/sbin/blkid
%{uclibc_root}/sbin/mkswap
%{uclibc_root}/sbin/sfdisk
%{uclibc_root}/sbin/swaplabel
%{uclibc_root}%{_bindir}/setterm
%endif

%files -n uuidd
%{_mandir}/man8/uuidd.8*
%{_unitdir}/uuidd.*
%{_sysconfdir}/tmpfiles.d/uuidd.conf
%attr(-, uuidd, uuidd) %{_sbindir}/uuidd
%dir %attr(2775, uuidd, uuidd) /var/lib/libuuid

%files -n %{libblkid}
%dir /etc/blkid
/%{_lib}/libblkid.so.%{blkid_major}*

%if %{with uclibc}
%files -n uclibc-%{libblkid}
%{uclibc_root}/%{_lib}/libblkid.so.%{blkid_major}*
%endif

%files -n %{devblkid}
%{_libdir}/libblkid.a
%if %{with uclibc}
%{uclibc_root}%{_libdir}/libblkid.so
%endif
%{_libdir}/libblkid.so
%{_includedir}/blkid
%{_mandir}/man3/libblkid.3*
%{_libdir}/pkgconfig/blkid.pc

%files -n %{libuuid}
/%{_lib}/libuuid.so.%{uuid_major}*

%if %{with uclibc}
%files -n uclibc-%{libuuid}
%{uclibc_root}/%{_lib}/libuuid.so.%{uuid_major}*
%endif

%files -n %{devuuid}
%{_libdir}/libuuid.a
%if %{with uclibc}
%{uclibc_root}%{_libdir}/libuuid.so
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

%files -n %{libmount}
/%{_lib}/libmount.so.%{mount_major}*

%if %{with uclibc}
%files -n uclibc-%{libmount}
%{uclibc_root}/%{_lib}/libmount.so.%{mount_major}*
%endif

%files -n %{devmount}
%{_includedir}/libmount/libmount.h
%if %{with uclibc}
%{uclibc_root}%{_libdir}/libmount.so
%endif
%{_libdir}/libmount.so
%{_libdir}/libmount.*a
%{_libdir}/pkgconfig/mount.pc

%changelog
* Wed Dec 13 2012 Per Øyvind Karlsen <peroyvind@mandriva.org> 2.22.2-1
- new version

* Wed Dec 12 2012 Per Øyvind Karlsen <peroyvind@mandriva.org> 2.22-7
- rebuild on ABF

* Sun Oct 28 2012 Per Øyvind Karlsen <peroyvind@mandriva.org> 2.22-6
+ Revision: 820149
- fix license
- use %%uclibc_configure macro
- drop patch for pulling in libintl, it's now rather done by latest uClibc
- reupload again due to package going missing in repos..

* Thu Oct 04 2012 Per Øyvind Karlsen <peroyvind@mandriva.org> 2.22-5
+ Revision: 818412
- make sure that we pull in latest rpm to get proper uclibc() deps
- add conflicts on older sysvinit-tools to handle sulogin being moved

* Thu Oct 04 2012 Per Øyvind Karlsen <peroyvind@mandriva.org> 2.22-4
+ Revision: 818396
- rebuild with fixed rpm for uclibc() deps

* Thu Oct 04 2012 Per Øyvind Karlsen <peroyvind@mandriva.org> 2.22-3
+ Revision: 818357
- make ncurses dependency versioned so that we're sure to pull in latest
- bump versioned uClibc-devel buildrequires
- build more uclibc linkd binaries

* Mon Sep 24 2012 Per Øyvind Karlsen <peroyvind@mandriva.org> 2.22-2
+ Revision: 817423
- don't bother passing '-fno-strict-aliasing'
- SILENCE: actually do the build of blkid as well
- package uClibc linked blkid
- add missing dependencies on uclibc libs for library packages
- be sure to build against latest uClibc with locale enabled
- fix and change to dynamic build against uclibc
- do uClibc build of libmount also

* Thu Sep 06 2012 Bernhard Rosenkraenzer <bero@bero.eu> 2.22-1
+ Revision: 816422
- Update to 2.22 final

  + Tomasz Pawel Gajc <tpg@mandriva.org>
    - spec file clean

* Sat Aug 25 2012 Tomasz Pawel Gajc <tpg@mandriva.org> 2.22-0.rc2.2
+ Revision: 815746
- move su.pamd and su-l.pamd from coreutils (needed for working su auth)
- add conflicts on coreutils older than 8.19-2
- add provides on /bin/su

* Mon Aug 20 2012 Bernhard Rosenkraenzer <bero@bero.eu> 2.22-0.rc2.1
+ Revision: 815458
- BuildRequires pkgconfig(systemd) for uuidd startup files
- Update to 2.22-rc2

* Tue Jun 19 2012 Tomasz Pawel Gajc <tpg@mandriva.org> 2.21.2-4
+ Revision: 806266
- use %%serverbuild_hardened macro
- enable --enable-new-mount (finally mount can handle x-* fstab options, like x-gvfs-show)

* Mon Jun 04 2012 Per Øyvind Karlsen <peroyvind@mandriva.org> 2.21.2-3
+ Revision: 802398
- add conflicts on util-linux 2.7.18-6 to avoid file conflicts with /etc/mtab

* Tue May 29 2012 Guilherme Moro <guilherme@mandriva.com> 2.21.2-2
+ Revision: 801040
- Own mtab now
  fix unused BR

* Sat May 26 2012 Bernhard Rosenkraenzer <bero@bero.eu> 2.21.2-1
+ Revision: 800780
- Update to 2.21.2

* Fri Mar 30 2012 Bernhard Rosenkraenzer <bero@bero.eu> 2.21.1-1
+ Revision: 788387
- Update to 2.21.1

  + Per Øyvind Karlsen <peroyvind@mandriva.org>
    - s/util-linux-ng/util-linux/

* Wed Mar 07 2012 Per Øyvind Karlsen <peroyvind@mandriva.org> 2.21-3
+ Revision: 782727
- s/sunsparc/sparcx/
- rebuild with internal dependency generator

* Tue Mar 06 2012 Bernhard Rosenkraenzer <bero@bero.eu> 2.21-2
+ Revision: 782473
- Fix login.defs parser in /bin/login, bug #65355

* Sun Feb 26 2012 Bernhard Rosenkraenzer <bero@bero.eu> 2.21-1
+ Revision: 780810
- Update to 2.21

* Sun Feb 19 2012 Tomasz Pawel Gajc <tpg@mandriva.org> 2.20.1-1
+ Revision: 777496
- update to new version 2.20.1
- fix find_lang macro

* Fri Feb 10 2012 Oden Eriksson <oeriksson@mandriva.com> 2.20-2
+ Revision: 772468
- fix deps

  + Per Øyvind Karlsen <peroyvind@mandriva.org>
    - drop uclibc build for now as it segfaults
    - rebuild without libtool .la files

* Sun Sep 04 2011 Tomasz Pawel Gajc <tpg@mandriva.org> 2.20-1
+ Revision: 698245
- update to new version 2.20
- rediff patches 3, 8, 115. 1202, 1212
- enable ddate
- disable mountpoint (already in systemd)

* Sat Jul 16 2011 Eugeni Dodonov <eugeni@mandriva.com> 2.19.1-1
+ Revision: 690114
- New version 2.19.1.

* Tue May 10 2011 Per Øyvind Karlsen <peroyvind@mandriva.org> 2.19-3
+ Revision: 673175
- link stuff with %%ldflags..
- enable uClibc build
- cleanups
- cleanups

* Tue Apr 05 2011 Funda Wang <fwang@mandriva.org> 2.19-2
+ Revision: 650758
- rebuild to obosletes old packages

* Wed Mar 30 2011 Eugeni Dodonov <eugeni@mandriva.com> 2.19-1
+ Revision: 649155
- Add libtool to BR
- Update to util-linux 2.19.
  Drop P20 and P21 (upstream)
  Rediff P116, P1207 and P1218.
- Util-linux-ng was renamed back to util-linux with 2.19 version.

* Sat Jan 01 2011 Funda Wang <fwang@mandriva.org> 2.18-3mdv2011.0
+ Revision: 627160
- add conflicts on ossp_uuid

* Mon Nov 29 2010 Andrey Borzenkov <arvidjaar@mandriva.org> 2.18-2mdv2011.0
+ Revision: 603118
- P20: agetty -s/-c support with fixes (GIT)
  P21: fsck -l support with whole disk locking fix (GIT)

* Sun Sep 05 2010 Tomasz Pawel Gajc <tpg@mandriva.org> 2.18-1mdv2011.0
+ Revision: 576013
- update to new version 2.18
- drop patches 15, 20 and 1220 as they were fixed by upstream
- update patch 1100
- rediff patch 1300
- package libmount
- protect majors everywhere
- compile with Os flag
- spec file clean

* Wed Jun 09 2010 Herton Ronaldo Krzesinski <herton@mandriva.com.br> 2.17.1-5mdv2010.1
+ Revision: 547295
- Apply "libblkid: fix infinite loop when probe chain bails out early"
  from upstream git, fixes mkinitrd hangs in nash for some users
  (#58697).

* Wed Mar 31 2010 Frederic Crozat <fcrozat@mandriva.com> 2.17.1-4mdv2010.1
+ Revision: 530431
- Replace file-dependencies with package dependencies

* Mon Mar 22 2010 Eugeni Dodonov <eugeni@mandriva.com> 2.17.1-3mdv2010.1
+ Revision: 526669
- Requiring both ncurses-devel and ncursesw-devel.
- cfdisk requires libncursesw to work properly in utf-8 environments (#58277)

* Mon Mar 15 2010 Herton Ronaldo Krzesinski <herton@mandriva.com.br> 2.17.1-2mdv2010.1
+ Revision: 519122
- libblkid: reset BLKID_TINY_DEV flag in blkid_probe_set_device
  (from Pascal Terjan). For example, fixes devices not detected
  anymore by nash-resolveDevice on some systems.

* Wed Feb 24 2010 Thomas Backlund <tmb@mandriva.org> 2.17.1-1mdv2010.1
+ Revision: 510759
- update to 2.17.1
- drop P12 (drbd crash fix, merged upstream)
- rediff P1100 (loop-AES support)

* Thu Feb 11 2010 Pascal Terjan <pterjan@mandriva.org> 2.17-2mdv2010.1
+ Revision: 504375
- Upstream patch fixing a crash in libblkid (#57325)

* Mon Jan 25 2010 Eugeni Dodonov <eugeni@mandriva.com> 2.17-1mdv2010.1
+ Revision: 496133
- Update to 2.17.
  Drop P10 (no longer used and dropped upstream).

  + Per Øyvind Karlsen <peroyvind@mandriva.org>
    - add uclibc static library to %%files conditionally
    - build uclibc linked static libraries

* Tue Dec 01 2009 Eugeni Dodonov <eugeni@mandriva.com> 2.16.2-1mdv2010.1
+ Revision: 472224
- Updated to 2.16.2.
  Rediff loopAES patch.
  Drop P12,P13,P14,P15 (merged upstream).

