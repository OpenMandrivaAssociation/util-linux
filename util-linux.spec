# Using LTO breaks building applications that use static libblkid
# with gcc.
# Currently that combination is needed for lvm2.
# Please remove _disable_lto if and only if you've fixed
# (or removed) lvm2.
%define _disable_lto 1
# To make the python modules happy
%define _disable_ld_no_undefined 1

%global __requires_exclude ^/bin/tcsh|^tcsh

%define blkid_major 1
%define libblkid %mklibname blkid %{blkid_major}
%define devblkid %mklibname blkid -d

%define fdisk_major 1
%define libfdisk %mklibname fdisk %{fdisk_major}
%define devfdisk %mklibname fdisk -d

%define uuid_major 1
%define libuuid %mklibname uuid %{uuid_major}
%define devuuid %mklibname uuid -d

%define ext2fs_major 2
%define libext2fs %mklibname ext2fs %{ext2fs_major}
%define devext2fs %mklibname ext2fs -d

%define mount_major 1
%define libmount %mklibname mount %{mount_major}
%define devmount %mklibname mount -d

%define smartcols_major 1
%define libsmartcols %mklibname smartcols %{smartcols_major}
%define devsmartcols %mklibname smartcols -d

%define git_url git://git.kernel.org/pub/scm/utils/util-linux/util-linux.git

%define build_bootstrap 0

# libuuid is used by libSM, which in turn is used by wine
%ifarch %{x86_64}
%bcond_without compat32
%else
%bcond_with compat32
%endif

%if %{with compat32}
%define lib32blkid libblkid%{blkid_major}
%define dev32blkid libblkid-devel

%define lib32fdisk libfdisk%{fdisk_major}
%define dev32fdisk libfdisk-devel

%define lib32uuid libuuid%{uuid_major}
%define dev32uuid libuuid-devel

%define lib32ext2fs libext2fs%{ext2fs_major}
%define dev32ext2fs libext2fs-devel

%define lib32mount libmount%{mount_major}
%define dev32mount libmount-devel

%define lib32smartcols libsmartcols%{smartcols_major}
%define dev32smartcols libsmartcols-devel
%endif

### Macros
%define no_hwclock_archs s390 s390x

%if !%{build_bootstrap}
%bcond_without python
%endif

#define beta rc2

Summary:	A collection of basic system utilities
Name:		util-linux
Version:	2.37
Release:	%{?beta:0.%{beta}.}2
License:	GPLv2 and GPLv2+ and BSD with advertising and Public Domain
Group:		System/Base
URL:		http://www.kernel.org/pub/linux/utils/util-linux
Source0:	http://www.kernel.org/pub/linux/utils/%{name}/v%(echo %{version} |cut -d. -f1-2)/%{name}-%{version}%{?beta:-%{beta}}.tar.xz
# based on Fedora pam files, with pam_selinux stripped out
Source1:	util-linux-login.pamd
Source2:	util-linux-remote.pamd
Source3:	util-linux-chsh-chfn.pamd
Source4:	util-linux-60-raw.rules
Source5:	util-linux-su.pamd
Source6:	util-linux-su-l.pamd
Source7:	util-linux-runuser.pamd
Source8:	util-linux-runuser-l.pamd
Source9:	%{name}.rpmlintrc
Source11:	uuidd-tmpfiles.conf
Source14:	uuidd.sysusers

# 151635 - making /var/log/lastlog
Patch5:		util-linux-2.26-login-lastlog-create.patch
# (tpg) ClearLinux patches
Patch2000:	0001-Speed-up-agetty-waits.patch
Patch2001:	0003-Recommend-1M-topology-size-if-none-set.patch

BuildRequires:	libtool
BuildRequires:	sed
BuildRequires:	bison
BuildRequires:	byacc
BuildRequires:	asciidoctor
BuildRequires:	systemd-rpm-macros
BuildRequires:	gettext-devel
BuildRequires:	pam-devel
BuildRequires:	utempter-devel
%if !%{build_bootstrap}
BuildRequires:	pkgconfig(ext2fs)
# (tpg) disable it as it is still EXPERIMENTAL
#BuildRequires:	pkgconfig(libcryptsetup)
%endif
BuildRequires:	pkgconfig(libcap-ng)
BuildRequires:	pkgconfig(ncursesw) >= 5.9-6.20120922.3
#BuildRequires:	termcap-devel
BuildRequires:	pkgconfig(slang)
BuildRequires:	pkgconfig(systemd)
BuildRequires:	pkgconfig(udev)
BuildRequires:	pkgconfig(zlib)
BuildRequires:	pkgconfig(libuser)
BuildRequires:	pkgconfig(readline)
BuildRequires:	pkgconfig(libpcre2-8)
BuildRequires:	kernel-release-headers
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
%rename		hardlink
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
Conflicts:	sysvinit-tools < 2.87-24
Conflicts:	bash-completion < 2:2.7-2
Conflicts:	rfkill < 0.5-10
Requires:	pam >= 1.3.0-1
Requires:	shadow >= 4.2.1-24
Requires:	%{libblkid} = %{EVRD}
Requires:	%{libfdisk} = %{EVRD}
Requires:	%{libmount} = %{EVRD}
Requires:	%{libuuid} = %{EVRD}
Requires:	%{libsmartcols} = %{EVRD}
Suggests:	%{name}-doc = %{EVRD}
%if %{with compat32}
BuildRequires:	libcrypt-devel
%endif

%description
The util-linux package contains a large variety of low-level system
utilities that are necessary for a Linux system to function.  Among
others, Util-linux-ng contains the fdisk configuration tool and the login
program.

%package -n %{libblkid}
Summary:	Block device ID library
Group:		System/Libraries
License:	LGPLv2+
Conflicts:	%{libext2fs} < 1.41.6-2mnb2

%description -n %{libblkid}
This is block device identification library, part of util-linux.

%package -n %{devblkid}
Summary:	Block device ID library
Group:		Development/C
License:	LGPLv2+
Requires:	%{libblkid} = %{version}-%{release}
Requires:	%{devuuid} = %{version}-%{release}
Conflicts:	%{devext2fs} < 1.41.6-2mnb2

%description -n %{devblkid}
This is the block device identification development library and headers,
part of util-linux.

%package -n %{libfdisk}
Summary:	Fdisk library
Group:		System/Libraries
License:	LGPLv2+

%description -n %{libfdisk}
This is fdisk library, part of util-linux.

%package -n %{devfdisk}
Summary:	Fdisk development library
Group:		Development/C
License:	LGPLv2+
Requires:	%{libfdisk} = %{version}-%{release}

%description -n %{devfdisk}
This is the fdisk development library and headers,
part of util-linux.

%package -n %{libuuid}
Summary:	Universally unique ID library
Group:		System/Libraries
License:	BSD
Conflicts:	%{libext2fs} < 1.41.8-2mnb2

%description -n %{libuuid}
This is the universally unique ID library, part of e2fsprogs.

The libuuid library generates and parses 128-bit universally unique
id's (UUID's).A UUID is an identifier that is unique across both
space and time, with respect to the space of all UUIDs.  A UUID can
be used for multiple purposes, from tagging objects with an extremely
short lifetime, to reliably identifying very persistent objects
across a network.

%package -n %{devuuid}
Summary:	Universally unique ID library
Group:		Development/C
License:	BSD
Conflicts:	%{libext2fs} < 1.41.8-2mnb2
Requires:	%{libuuid} = %{version}

%description -n %{devuuid}
This is the universally unique ID development library and headers,
part of e2fsprogs.

The libuuid library generates and parses 128-bit universally unique
id's (UUID's).A UUID is an identifier that is unique across both
space and time, with respect to the space of all UUIDs.  A UUID can
be used for multiple purposes, from tagging objects with an extremely
short lifetime, to reliably identifying very persistent objects
across a network.

%package -n uuidd
Summary:	Helper daemon to guarantee uniqueness of time-based UUIDs
Group:		System/Servers
License:	GPLv2
Requires(pre):	glibc
Requires(pre):	shadow
Requires(pre):	passwd
%systemd_requires

%description -n uuidd
The uuidd package contains a userspace daemon (uuidd) which guarantees
uniqueness of time-based UUID generation even at very high rates on
SMP systems.

%package -n %{libmount}
Summary:	Universal mount library
Group:		System/Libraries
License:	LGPLv2+

%description -n %{libmount}
The libmount library is used to parse /etc/fstab,
/etc/mtab and /proc/self/mountinfo files,
manage the mtab file, evaluate mount options, etc.

%package -n %{devmount}
Summary:	Universally unique ID library
Group:		Development/C
License:	LGPLv2+
Requires:	%{libmount} = %{EVRD}

%description -n %{devmount}
Development files and headers for libmount library.

%package -n %{libsmartcols}
Summary:	Formatting library for ls-like programs
Group:		System/Libraries
License:	LGPL2+
Requires:	filesystem >= 3.0-9

%description -n %{libsmartcols}
The libsmartcols library is used to format output,
for ls-like terminal programs.

%package -n %{devsmartcols}
Summary:	Formatting library for ls-like programs
Group:		Development/C
License:	LGPL2+
Requires:	%{libsmartcols} = %{EVRD}

%description -n %{devsmartcols}
Development files and headers for libsmartcols library.

%package user
Summary:	libuser based util-linux utilities
Group:		System/Base
Requires:	%{name} = %{EVRD}

%description -n util-linux-user
chfn and chsh utilities with dependence on libuser.

%if %{with python}
%package -n python-libmount
Summary:	Python bindings for the libmount library
Group:		Development/Python
Requires:	%{libmount} = %{EVRD}
BuildRequires:	pkgconfig(python3)

%description -n python-libmount
The libmount-python package contains a module that permits applications
written in the Python programming language to use the interface
supplied by the libmount library to work with mount tables (fstab,
mountinfo, etc) and mount filesystems.
%endif

%package -n rfkill
Summary:	Simple /dev/rfkill userspace tool
Group:		System/Base
Conflicts:	bash-completion < 2:2.7-2

%description -n rfkill
Rfkill is a simple userspace tool to manipulate /dev/rfkill.
It's needed to enable and disable wireless and bluetooth from
userspace beginning with 2.6.31 series kernels.

%package doc
Summary:	Documentation for %{name}
Group:		Books/Other

%description doc
Documentation and manuals for %{name}.

%if %{with compat32}
%package -n %{lib32blkid}
Summary:	Block device ID library (32-bit)
Group:		System/Libraries
License:	LGPLv2+

%description -n %{lib32blkid}
This is block device identification library, part of util-linux.

%package -n %{dev32blkid}
Summary:	Block device ID library (32-bit)
Group:		Development/C
License:	LGPLv2+
Requires:	%{lib32blkid} = %{version}-%{release}
Requires:	%{dev32uuid} = %{version}-%{release}
Requires:	%{devblkid} = %{EVRD}

%description -n %{dev32blkid}
This is the block device identification development library and headers,
part of util-linux.

%package -n %{lib32fdisk}
Summary:	Fdisk library (32-bit)
Group:		System/Libraries
License:	LGPLv2+

%description -n %{lib32fdisk}
This is fdisk library, part of util-linux.

%package -n %{dev32fdisk}
Summary:	Fdisk development library (32-bit)
Group:		Development/C
License:	LGPLv2+
Requires:	%{lib32fdisk} = %{version}-%{release}
Requires:	%{devfdisk} = %{EVRD}

%description -n %{dev32fdisk}
This is the fdisk development library and headers,
part of util-linux.

%package -n %{lib32uuid}
Summary:	Universally unique ID library (32-bit)
Group:		System/Libraries
License:	BSD

%description -n %{lib32uuid}
This is the universally unique ID library, part of e2fsprogs.

The libuuid library generates and parses 128-bit universally unique
id's (UUID's).A UUID is an identifier that is unique across both
space and time, with respect to the space of all UUIDs.  A UUID can
be used for multiple purposes, from tagging objects with an extremely
short lifetime, to reliably identifying very persistent objects
across a network.

%package -n %{dev32uuid}
Summary:	Universally unique ID library (32-bit)
Group:		Development/C
License:	BSD
Requires:	%{lib32uuid} = %{version}
Requires:	%{devuuid} = %{EVRD}

%description -n %{dev32uuid}
This is the universally unique ID development library and headers,
part of e2fsprogs.

The libuuid library generates and parses 128-bit universally unique
id's (UUID's).A UUID is an identifier that is unique across both
space and time, with respect to the space of all UUIDs.  A UUID can
be used for multiple purposes, from tagging objects with an extremely
short lifetime, to reliably identifying very persistent objects
across a network.

%package -n %{lib32mount}
Summary:	Universal mount library (32-bit)
Group:		System/Libraries
License:	LGPLv2+

%description -n %{lib32mount}
The libmount library is used to parse /etc/fstab,
/etc/mtab and /proc/self/mountinfo files,
manage the mtab file, evaluate mount options, etc.

%package -n %{dev32mount}
Summary:	Universally unique ID library (32-bit)
Group:		Development/C
License:	LGPLv2+
Requires:	%{lib32mount} = %{EVRD}
Requires:	%{devmount} = %{EVRD}

%description -n %{dev32mount}
Development files and headers for libmount library.

%package -n %{lib32smartcols}
Summary:	Formatting library for ls-like programs (32-bit)
Group:		System/Libraries
License:	LGPL2+
Requires:	filesystem >= 3.0-9

%description -n %{lib32smartcols}
The libsmartcols library is used to format output,
for ls-like terminal programs.

%package -n %{dev32smartcols}
Summary:	Formatting library for ls-like programs (32-bit)
Group:		Development/C
License:	LGPL2+
Requires:	%{lib32smartcols} = %{EVRD}
Requires:	%{devsmartcols} = %{EVRD}

%description -n %{dev32smartcols}
Development files and headers for libsmartcols library.
%endif

%prep
%autosetup -p1 -n %{name}-%{version}%{?beta:-%{beta}}

export CONFIGURE_TOP="`pwd`"

%if %{with compat32}
mkdir build32
cd build32
%configure32 \
	--enable-static=yes \
	--disable-all-programs \
	--disable-makeinstall-chown \
	--disable-rpath \
	--enable-libuuid \
	--enable-libblkid \
	--enable-libmount \
	--enable-libsmartcols \
	--enable-libfdisk \
	--without-audit \
	--without-python \
	--without-selinux \
	--without-udev \
	--without-utempter \
	--without-systemd \
	--without-cryptsetup \
	--without-readline
cd ..
%endif


mkdir build
cd build
%configure \
	--bindir=/bin \
	--sbindir=/sbin \
	--libdir=/%{_lib} \
	--enable-static=yes \
	--enable-wall \
	--enable-partx \
	--enable-kill \
	--enable-write \
	--enable-mountpoint \
	--enable-raw \
	--disable-makeinstall-chown \
	--disable-rpath \
	--without-audit \
	--with-python=3 \
	--without-selinux \
	--with-udev \
	--with-utempter \
	--enable-chfn-chsh \
	--enable-tunelp \
	--enable-nologin \
	--with-systemd \
	--with-readline \
	--with-cryptsetup \
	--enable-sulogin-emergency-mount \
	--with-systemdsystemunitdir=%{_unitdir}

%build
%serverbuild_hardened
unset LINGUAS || :

%if %{with compat32}
%make_build -C build32
%endif

# build util-linux
%make_build -C build REALTIME_LIBS="-lrt -lpthread"

%install
mkdir -p %{buildroot}/{bin,sbin}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_infodir}
mkdir -p %{buildroot}%{_mandir}/man{1,6,8,5}
mkdir -p %{buildroot}%{_sbindir}
mkdir -p %{buildroot}%{_sysconfdir}/{pam.d,blkid}

%if %{with compat32}
%make_install -C build32
%endif

# install util-linux
%make_install -C build MANDIR=%{buildroot}%{_mandir} INFODIR=%{buildroot}%{_infodir}

# (cg) Remove unwanted binaries (and their corresponding man pages)
for unwanted in %{unwanted}; do
  rm -f %{buildroot}{%{_bindir},%{_sbindir}}/$unwanted
  rm -f %{buildroot}%{_mandir}/{,{??,??_??}/}man*/$unwanted.[[:digit:]]*
done

# Kept here because it goes with agetty
cat >%{buildroot}%{_sysconfdir}/issue <<'EOF'
\S{PRETTY_NAME} for \m
Kernel \r on \4 / \l
EOF

echo '.so man8/raw.8' > %{buildroot}%{_mandir}/man8/rawdevices.8
# see RH bugzilla #216664
install -D -p -m 644 %{SOURCE4} %{buildroot}%{_udevrulesdir}/60-raw.rules

# Correct mail spool path.
sed -i -e 's,/usr/spool/mail,/var/spool/mail,' %{buildroot}%{_mandir}/man1/login.1

%ifarch %{sparcx}
rm %{buildroot}%{_bindir}/sunhostid
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
  cd %{buildroot}%{_sysconfdir}/pam.d
  install -m 644 %{SOURCE1} ./login
  install -m 644 %{SOURCE2} ./remote
  install -m 644 %{SOURCE3} ./chsh
  install -m 644 %{SOURCE3} ./chfn
  install -m 644 %{SOURCE5} ./su
  install -m 644 %{SOURCE6} ./su-l
  install -m 644 %{SOURCE7} ./runuser
  install -m 644 %{SOURCE8} ./runuser-l
  cd -
}

# This has dependencies on stuff in /usr
mv %{buildroot}{/sbin/,/usr/sbin}/cfdisk

%ifarch ppc
cp -f ./clock-ppc %{buildroot}/sbin/clock-ppc
mv %{buildroot}/sbin/hwclock %{buildroot}/sbin/clock-rs6k
ln -sf clock-rs6k %{buildroot}/sbin/hwclock
%endif
ln -sf ../../sbin/hwclock %{buildroot}%{_sbindir}/hwclock
ln -sf ../../sbin/clock %{buildroot}%{_sbindir}/clock
ln -sf hwclock %{buildroot}/sbin/clock
# (tpg) compat symlink
ln -sf ../bin/hardlink %{buildroot}%{_sbindir}/hardlink
ln -sf ../../sbin/pivot_root %{buildroot}%{_sbindir}/pivot_root

install -D -p -m 644 %{SOURCE11} %{buildroot}%{_tmpfilesdir}/uuidd.conf
install -D -p -m 644 %{SOURCE14} %{buildroot}%{_sysusersdir}/uuidd.conf

# And a dirs uuidd needs that the makefiles don't create
install -d %{buildroot}/var/lib/libuuid

# move flock in /bin, required for udev
# logger is useful in initscripts while /usr isn't mounted as well
# ionice needed for readahead_early
for p in flock logger ionice; do
    mv %{buildroot}{%{_bindir},/bin}/$p
    ln -sf ../../bin/$p %{buildroot}%{_bindir}/$p
done

# Final cleanup
%ifarch %no_hwclock_archs
rm %{buildroot}/sbin/{hwclock,clock} %{buildroot}%{_mandir}/man8/hwclock.8* %{buildroot}/usr/sbin/{hwclock,clock}
%endif
%ifarch s390 s390x
rm %{buildroot}/usr/{bin,sbin}/{tunelp,floppy} %{buildroot}%{_mandir}/man8/{tunelp,floppy}.8*
%endif

# deprecated commands
for I in /sbin/mkfs.bfs %{_bindir}/scriptreplay; do
    rm %{buildroot}$I
done

# deprecated man pages
for I in man8/mkfs.bfs.8 man1/scriptreplay.1; do
    rm %{buildroot}%{_mandir}/${I}*
done

# we install getopt/getopt-*.{bash,tcsh} as doc files
# note: versions <=2.12 use path "%{_datadir}/misc/getopt/*"
chmod 644 misc-utils/getopt-*.{bash,tcsh}

# link mtab
ln -sf ../proc/self/mounts %{buildroot}/etc/mtab

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

install -d %{buildroot}%{_presetdir}
cat > %{buildroot}%{_presetdir}/86-fstrim.preset << EOF
enable fstrim.timer
EOF



install -d %{buildroot}%{_presetdir}
cat > %{buildroot}%{_presetdir}/86-uuidd.preset << EOF
enable uuidd.socket
enable uuidd.service
EOF

%find_lang %{name} %{name}.lang

# the files section supports only one -f option...
mv %{name}.lang %{name}.files

# create list of setarch(8) symlinks
find  %{buildroot}%{_bindir}/ -regextype posix-egrep -type l \
	-regex ".*(linux32|linux64|s390|s390x|i386|ppc|ppc64|ppc32|sparc|sparc64|sparc32|sparc32bash|mips|mips64|mips32|ia64|x86_64|znver1|uname26)$" \
	-printf "%{_bindir}/%f\n" >> %{name}.files

find  %{buildroot}%{_mandir}/man8 -regextype posix-egrep  \
	-regex ".*(linux32|linux64|s390|s390x|i386|ppc|ppc64|ppc32|sparc|sparc64|sparc32|sparc32bash|mips|mips64|mips32|ia64|x86_64|znver1|uname26)\.8.*" \
	-printf "%{_mandir}/man8/%f*\n" >> %{name}.files

%pre -p <lua>
if arg[2] >= 2 then
	st = posix.stat("/etc/mtab")
	if st and st.type ~= "link" then
		posix.unlink("/etc/mtab")
		posix.link("/proc/mounts", "/etc/mtab", true)
	end
end

%post -p <lua>
if arg[2] >= 2 then
	if posix.stat("/etc/blkid.tab") then
		os.rename("/etc/blkid.tab", "/etc/blkid/blkid.tab")
	end
	if posix.stat("/etc/blkid.tab.old") then
		os.rename("/etc/blkid.tab.old", "/etc/blkid/blkid.tab.old")
	end
end

%pre -n uuidd
getent group uuidd >/dev/null || groupadd -r uuidd
getent passwd uuidd >/dev/null || \
useradd -r -g uuidd -d /var/lib/libuuid -s /sbin/nologin \
    -c "UUID generator helper daemon" uuidd
exit 0

%post -n uuidd
%systemd_post uidd.socket
%systemd_post uuidd.service

%preun -n uuidd
%systemd_preun uuidd.socket
%systemd_preun uuidd.service

%postun -n uuidd
%systemd_postun_with_restart uuidd.socket
%systemd_postun_with_restart uuidd.service

%files -f %{name}.files
/bin/dmesg
%attr(755,root,root) /bin/login
/bin/lsblk
/bin/more
/bin/kill
/bin/taskset
/bin/ionice
/bin/findmnt
/bin/mountpoint
%{_bindir}/chmem
%{_bindir}/fincore
%{_bindir}/lsmem
%{_bindir}/nsenter
%{_bindir}/setpriv
%{_bindir}/irqtop
%{_bindir}/lsirq
/bin/su
%attr(2555,root,tty) %{_bindir}/wall
/bin/wdctl
/bin/raw
%dir /etc/blkid
%{_udevrulesdir}/60-raw.rules
%config(noreplace) %{_sysconfdir}/pam.d/login
%config(noreplace) %{_sysconfdir}/pam.d/remote
%config(noreplace) %{_sysconfdir}/pam.d/su
%config(noreplace) %{_sysconfdir}/pam.d/su-l
%config(noreplace) %{_sysconfdir}/pam.d/runuser
%config(noreplace) %{_sysconfdir}/pam.d/runuser-l
%config(noreplace) %{_sysconfdir}/issue
/etc/mtab
/sbin/agetty
/sbin/blkid
/sbin/blkdiscard
/sbin/blkzone
/sbin/blockdev
/sbin/fstrim
/sbin/pivot_root
%{_sbindir}/pivot_root
/sbin/ctrlaltdel
/sbin/addpart
/sbin/delpart
/sbin/partx
/sbin/fsfreeze
/sbin/swaplabel
/sbin/runuser
%ifarch %ix86 alpha ia64 x86_64 s390 s390x ppc ppc64 %{sparcx} %mips %arm aarch64 znver1 riscv64
/sbin/sfdisk
%{_sbindir}/cfdisk
%endif
/sbin/fdisk
%ifnarch %no_hwclock_archs
/sbin/clock
%{_sbindir}/clock
/sbin/hwclock
/usr/sbin/hwclock
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
/sbin/zramctl
%{_bindir}/chrt
%{_bindir}/ionice
%{_bindir}/cal
%{_bindir}/choom
%{_bindir}/col
%{_bindir}/colcrt
%{_bindir}/colrm
%{_bindir}/column
%ifarch alpha ppc ppc64 %{sparcx} %mips
%{_bindir}/cytune
%endif
%{_bindir}/eject
/bin/flock
%{_bindir}/flock
%{_bindir}/fallocate
%{_bindir}/getopt
%{_bindir}/hardlink
%{_sbindir}/hardlink
%{_bindir}/hexdump
%{_bindir}/ipcrm
%{_bindir}/ipcs
%{_bindir}/isosize
/bin/logger
%{_bindir}/last
%{_bindir}/lastb
%{_bindir}/logger
%{_bindir}/look
%{_bindir}/lslocks
%{_bindir}/lslogins
%{_bindir}/lsipc
%{_bindir}/lsns
%{_bindir}/mcookie
%{_bindir}/mesg
%{_bindir}/utmpdump
%ifarch %{ix86} alpha ia64 x86_64 s390 s390x ppc ppc64 %{sparcx} %{mips} %{arm} aarch64 znver1 riscv64
/sbin/fsck.cramfs
/sbin/mkfs.cramfs
%endif
/sbin/fsck.minix
/sbin/mkfs.minix
/sbin/chcpu
%{_bindir}/namei
%{_bindir}/prlimit
%{_bindir}/rename
%{_bindir}/renice
%{_bindir}/rev
%{_bindir}/script
%{_bindir}/scriptlive
%{_bindir}/setarch
%{_bindir}/setsid
%{_bindir}/setterm
%ifarch %{sparcx}
%{_bindir}/sunhostid
%endif
%{_bindir}/ul
%{_bindir}/unshare
%{_bindir}/uuidgen
%{_bindir}/uuidparse
%{_bindir}/whereis
%{_bindir}/ipcmk
%{_bindir}/lscpu
%attr(2755,root,tty) %{_bindir}/write
%{_bindir}/uclampset
%{_sbindir}/readprofile
%ifnarch s390 s390x
%{_sbindir}/tunelp
%endif
%{_sbindir}/rtcwake
%{_sbindir}/ldattach
%{_sbindir}/resizepart
%attr(4755,root,root) /bin/mount
%attr(4755,root,root) /bin/umount
/sbin/swapon
/sbin/swapoff
/sbin/switch_root
/sbin/losetup
/sbin/wipefs
%{_presetdir}/86-fstrim.preset
%{_unitdir}/fstrim.*
%{_datadir}/bash-completion/completions/*

%files doc
%doc %{_docdir}/%{name}
%{_mandir}/man8/agetty.8*
%{_mandir}/man8/partx.8*
%{_mandir}/man8/addpart.8*
%{_mandir}/man8/blkzone.8*
%{_mandir}/man8/chmem.8*
%ifarch alpha ppc ppc64 %{sparcx} %mips
%{_mandir}/man8/cytune.8*
%endif
%{_mandir}/man8/delpart.8*
%{_mandir}/man8/findmnt.8*
%{_mandir}/man8/fsfreeze.8*
%{_mandir}/man8/fstrim.8*
%ifnarch %no_hwclock_archs
%{_mandir}/man8/hwclock.8*
%endif
%{_mandir}/man8/lsblk.8*
%{_mandir}/man8/nologin.8*
%{_mandir}/man8/swaplabel.8*
%{_mandir}/man1/irqtop.1*
%{_mandir}/man1/lsirq.1*
%{_mandir}/man1/lsmem.1*
%{_mandir}/man1/fincore.1*
%{_mandir}/man1/hardlink.1*
%{_mandir}/man1/mountpoint.1*
%{_mandir}/man1/nsenter.1*
%{_mandir}/man1/setpriv.1*
%{_mandir}/man1/scriptlive.1*
%{_mandir}/man1/wall.1*
%{_mandir}/man5/adjtime_config.5*
%{_mandir}/man8/sfdisk.8*
%{_mandir}/man8/cfdisk.8*
%{_mandir}/man8/fdisk.8*
%{_mandir}/man1/cal.1*
%{_mandir}/man8/chcpu.8*
%{_mandir}/man1/choom.1*
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
%{_mandir}/man1/last.1*
%{_mandir}/man1/lastb.1.*
%{_mandir}/man1/logger.1*
%{_mandir}/man1/login.1*
%{_mandir}/man1/look.1*
%{_mandir}/man1/lsipc.1*
%{_mandir}/man1/mcookie.1*
%{_mandir}/man1/mesg.1*
%{_mandir}/man1/more.1*
%{_mandir}/man1/namei.1*
%{_mandir}/man1/prlimit.1*
%{_mandir}/man1/rename.1*
%{_mandir}/man1/rev.1*
%{_mandir}/man1/script.1*
%{_mandir}/man1/setterm.1*
%{_mandir}/man1/ul.1*
%{_mandir}/man1/uuidgen.1*
%{_mandir}/man1/uuidparse.1*
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
%{_mandir}/man1/lslogins.1*
%{_mandir}/man1/su.1*
%{_mandir}/man3/uuid_generate_time_safe.3*
%{_mandir}/man8/blockdev.8*
%{_mandir}/man8/blkid.8*
%{_mandir}/man8/blkdiscard.8*
%{_mandir}/man8/ctrlaltdel.8*
%{_mandir}/man8/findfs.8*
%{_mandir}/man8/fsck.8*
%{_mandir}/man8/fsck.cramfs.8*
%{_mandir}/man8/isosize.8*
%{_mandir}/man8/lslocks.8*
%{_mandir}/man8/lsns.8*
%{_mandir}/man8/mkfs.8*
%{_mandir}/man8/mkfs.cramfs.8*
%{_mandir}/man8/mkswap.8*
%{_mandir}/man8/pivot_root.8*
%{_mandir}/man8/raw.8*
%{_mandir}/man8/rawdevices.8*
%{_mandir}/man8/readprofile.8*
%{_mandir}/man8/resizepart.8*
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
%{_mandir}/man5/fstab.5*
%{_mandir}/man5/terminal-colors.d.5*
%{_mandir}/man8/mount.8*
%{_mandir}/man8/swapoff.8*
%{_mandir}/man8/swapon.8*
%{_mandir}/man8/switch_root.8*
%{_mandir}/man1/runuser.1*
%{_mandir}/man8/umount.8*
%{_mandir}/man8/losetup.8*
%{_mandir}/man8/zramctl.8.*
%{_mandir}/man1/uclampset.1.*

%files user
%config(noreplace) %{_sysconfdir}/pam.d/chfn
%config(noreplace) %{_sysconfdir}/pam.d/chsh
%attr(4711,root,root) %{_bindir}/chfn
%attr(4711,root,root) %{_bindir}/chsh
%{_mandir}/man1/chfn.1*
%{_mandir}/man1/chsh.1*

%files -n uuidd
%{_mandir}/man8/uuidd.8*
%{_presetdir}/86-uuidd.preset
%{_unitdir}/uuidd.*
%{_tmpfilesdir}/uuidd.conf
%{_sysusersdir}/uuidd.conf
%attr(-, uuidd, uuidd) %{_sbindir}/uuidd
%dir %attr(2775, uuidd, uuidd) /var/lib/libuuid

%files -n rfkill
%{_sbindir}/rfkill
%{_mandir}/man8/rfkill.8*

%files -n %{libblkid}
/%{_lib}/libblkid.so.%{blkid_major}*

%files -n %{devblkid}
%{_libdir}/libblkid.a
%{_libdir}/libblkid.so
%{_includedir}/blkid
%{_mandir}/man3/libblkid.3*
%{_libdir}/pkgconfig/blkid.pc

%files -n %{libfdisk}
/%{_lib}/libfdisk.so.%{fdisk_major}*

%files -n %{devfdisk}
%{_libdir}/libfdisk.a
%{_libdir}/libfdisk.so
%{_includedir}/libfdisk
%{_libdir}/pkgconfig/fdisk.pc

%files -n %{libuuid}
/%{_lib}/libuuid.so.%{uuid_major}*

%files -n %{devuuid}
%{_libdir}/libuuid.a
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

%files -n %{devmount}
%{_includedir}/libmount/libmount.h
%{_libdir}/libmount.so
%{_libdir}/libmount.a
%{_libdir}/pkgconfig/mount.pc

%if %{with python}
%files -n python-libmount
%dir %{python_sitearch}/libmount
%{py_platsitedir}/libmount/*
%endif

%files -n %{libsmartcols}
/%{_lib}/libsmartcols.so.%{smartcols_major}*

%files -n %{devsmartcols}
%{_includedir}/libsmartcols
%{_libdir}/libsmartcols.so
%{_libdir}/libsmartcols.*a
%{_libdir}/pkgconfig/smartcols.pc

%if %{with compat32}
%files -n %{lib32blkid}
%{_prefix}/lib/libblkid.so.%{blkid_major}*

%files -n %{dev32blkid}
%{_prefix}/lib/libblkid.a
%{_prefix}/lib/libblkid.so
%{_prefix}/lib/pkgconfig/blkid.pc

%files -n %{lib32fdisk}
%{_prefix}/lib/libfdisk.so.%{fdisk_major}*

%files -n %{dev32fdisk}
%{_prefix}/lib/libfdisk.a
%{_prefix}/lib/libfdisk.so
%{_prefix}/lib/pkgconfig/fdisk.pc

%files -n %{lib32uuid}
%{_prefix}/lib/libuuid.so.%{uuid_major}*

%files -n %{dev32uuid}
%{_prefix}/lib/libuuid.a
%{_prefix}/lib/libuuid.so
%{_prefix}/lib/pkgconfig/uuid.pc

# 32-bit libmount isn't used anywhere
%files -n %{lib32mount}
%{_prefix}/lib/libmount.so.%{mount_major}*

%files -n %{dev32mount}
%{_prefix}/lib/libmount.so
%{_prefix}/lib/libmount.a
%{_prefix}/lib/pkgconfig/mount.pc

%files -n %{lib32smartcols}
%{_prefix}/lib/libsmartcols.so.%{smartcols_major}*

%files -n %{dev32smartcols}
%{_prefix}/lib/libsmartcols.so
%{_prefix}/lib/libsmartcols.*a
%{_prefix}/lib/pkgconfig/smartcols.pc
%endif
