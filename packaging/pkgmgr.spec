#sbs-git:slp/pkgs/s/slp-pkgmgr pkgmgr 0.1.103 29b53909a5d6e8728429f0a188177eac691cb6ce
Name:       pkgmgr
Summary:    Packager Manager client library package
Version:    0.1.136
Release:    1
Group:      System/Libraries
License:    Apache License, Version 2.0
Source0:    %{name}-%{version}.tar.gz
BuildRequires:  cmake
BuildRequires:  gettext-tools
BuildRequires:  pkgconfig(ecore)
BuildRequires:  pkgconfig(security-server)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(aul)
BuildRequires:  pkgconfig(ail)
BuildRequires:  pkgconfig(appcore-efl)
BuildRequires:  pkgconfig(libxml-2.0)


%description
Packager Manager client library package for packaging


%package client
Summary:    Package Manager client library develpoment package
Group:      TO_BE/FILLED_IN
Requires:   %{name} = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description client
Package Manager client library develpoment package for packaging

%package client-devel
Summary:    Package Manager client library develpoment package
Group:      TO_BE/FILLED_IN
Requires:   %{name} = %{version}-%{release}

%description client-devel
Package Manager client library develpoment package for packaging

%package server
Summary:    Package Manager server
Group:      TO_BE/FILLED_IN
Requires:   %{name} = %{version}-%{release}

%description server
Package Manager server for packaging

%package installer
Summary:    Library for installer frontend/backend.
Group:      TO_BE/FILLED_IN
Requires:   %{name} = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description installer
Library for installer frontend/backend for packaging.

%package installer-devel
Summary:    Dev package for libpkgmgr-installer
Group:      TO_BE/FILLED_IN
Requires:   %{name} = %{version}-%{release}

%description installer-devel
Dev package for libpkgmgr-installer for packaging.

%package parser
Summary:    Library for manifest parser
Group:      TO_BE/FILLED_IN
Requires:   %{name} = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description parser
Library for manifest parser

%package parser-devel
Summary:    Dev package for libpkgmgr-parser
Group:      TO_BE/FILLED_IN
Requires:   %{name} = %{version}-%{release}

%description parser-devel
Dev package for libpkgmgr-parser
%package types-devel
Summary:    Package Manager manifest parser develpoment package
Group:      TO_BE/FILLED_IN
Requires:   %{name} = %{version}-%{release}

%description types-devel
Package Manager client types develpoment package for packaging


%prep
%setup -q

cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}

%build

make %{?jobs:-j%jobs}
%install
rm -rf %{buildroot}
%make_install


%post
/sbin/ldconfig

mkdir -p /usr/etc/package-manager/backend
mkdir -p /usr/etc/package-manager/backendlib

# For pkgmgr-install:
# Update mime database to support package mime types
update-mime-database /usr/share/mime

%post server

/sbin/ldconfig
mkdir -p /usr/etc/package-manager/server

%post client -p /sbin/ldconfig

%postun client -p /sbin/ldconfig

%post installer -p /sbin/ldconfig

%postun installer -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%{_bindir}/pkgcmd
%{_bindir}/pkginfo
%{_bindir}/pkg_initdb
%exclude %{_bindir}/pkgmgr_backend_sample
%exclude %{_includedir}/pkgmgr/comm_client.h
%exclude %{_includedir}/pkgmgr/comm_config.h
%exclude %{_includedir}/pkgmgr/comm_status_broadcast_server.h
%exclude %{_libdir}/libpkgmgr_backend_lib_sample.so
%exclude /usr/etc/package-manager/server/queue_status

%files client
%defattr(-,root,root,-)
%{_prefix}/etc/package-manager/pkg_path.conf
%{_datadir}/mime/packages/mime.wac.xml
%{_bindir}/pkgmgr-install
%{_libdir}/libpkgmgr-client.so.*
%{_datadir}/applications/org.tizen.pkgmgr-install.desktop
%{_datadir}/packages/org.tizen.pkgmgr-install.xml

%files client-devel
%defattr(-,root,root,-)
%{_includedir}/package-manager.h
%{_libdir}/pkgconfig/pkgmgr.pc
%{_libdir}/libpkgmgr-client.so

%files server
%defattr(-,root,root,-)
%{_datadir}/dbus-1/services/org.tizen.slp.pkgmgr.service
%{_bindir}/pkgmgr-server
%{_datadir}/locale/*/LC_MESSAGES/*.mo

%files installer
%defattr(-,root,root,-)
%{_libdir}/libpkgmgr_installer.so.*
%{_libdir}/libpkgmgr_installer_status_broadcast_server.so.*
%{_libdir}/libpkgmgr_installer_client.so.*

%files installer-devel
%defattr(-,root,root,-)
%{_includedir}/pkgmgr/pkgmgr_installer.h
%{_libdir}/pkgconfig/pkgmgr-installer-status-broadcast-server.pc
%{_libdir}/pkgconfig/pkgmgr-installer.pc
%{_libdir}/pkgconfig/pkgmgr-installer-client.pc
%{_libdir}/libpkgmgr_installer.so
%{_libdir}/libpkgmgr_installer_client.so
%{_libdir}/libpkgmgr_installer_status_broadcast_server.so

%files parser
%defattr(-,root,root,-)
%{_libdir}/libpkgmgr_parser.so.*
%{_prefix}/etc/package-manager/preload/preload_list.txt
%{_prefix}/etc/package-manager/preload/manifest.xsd
%{_prefix}/etc/package-manager/preload/xml.xsd
%{_libdir}/libpkgmgr_parser_lib_sample.so

%files parser-devel
%defattr(-,root,root,-)
%{_includedir}/pkgmgr/pkgmgr_parser.h
%{_libdir}/pkgconfig/pkgmgr-parser.pc
%{_libdir}/libpkgmgr_parser.so



%files types-devel
%defattr(-,root,root,-)
%{_includedir}/package-manager-types.h
%{_includedir}/package-manager-plugin.h
%{_libdir}/pkgconfig/pkgmgr-types.pc
