Name:       pkgmgr
Summary:    Packager Manager client library package
Version:    0.3.37
Release:    1
Group:      System/Libraries
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
BuildRequires:  cmake
BuildRequires:  pkgconfig(security-server)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(gio-unix-2.0)
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(bundle)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(iniparser)
BuildRequires:  pkgconfig(minizip)
BuildRequires:  pkgconfig(xdgmime)
BuildRequires:  pkgconfig(vasum)
BuildRequires:  pkgconfig(db-util)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgmgr-info-parser-devel

%define appfw_feature_expansion_pkg_install 1
%define appfw_feature_delta_update 1
%define appfw_feature_drm_enable 1
%define appfw_feature_mount_install 0

%if 0%{?appfw_feature_drm_enable}
BuildRequires:  pkgconfig(drm-service-core-tizen)
%endif

%description
Packager Manager client library package for packaging

Requires(post): pkgmgr-info

%package client
Summary:    Package Manager client library develpoment package
Group:      TO_BE/FILLED_IN
Requires:   %{name} = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
Requires(post): pkgmgr

%description client
Package Manager client library develpoment package for packaging

%package client-devel
Summary:    Package Manager client library develpoment package
Group:      TO_BE/FILLED_IN
Requires:   %{name} = %{version}-%{release}

%description client-devel
Package Manager client library develpoment package for packaging

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


%package types-devel
Summary:    Package Manager manifest parser develpoment package
Group:      TO_BE/FILLED_IN
Requires:   %{name} = %{version}-%{release}

%description types-devel
Package Manager client types develpoment package for packaging


%prep
%setup -q

%build
%if 0%{?tizen_build_binary_release_type_eng}
export CFLAGS="$CFLAGS -DTIZEN_ENGINEER_MODE"
export CXXFLAGS="$CXXFLAGS ?DTIZEN_ENGINEER_MODE"
export FFLAGS="$FFLAGS -DTIZEN_ENGINEER_MODE"
%endif

%if 0%{?appfw_feature_expansion_pkg_install}
_EXPANSION_PKG_INSTALL=ON
%else
_EXPANSION_PKG_INSTALL=OFF
%endif

%if 0%{?appfw_feature_delta_update}
_DELTA_UPDATE=ON
%else
_DELTA_UPDATE=OFF
%endif

%if 0%{?appfw_feature_drm_enable}
_DRM_ENABLE=ON
%else
_DRM_ENABLE=OFF
%endif

%if 0%{?appfw_feature_mount_install}
_MOUNT_INSTALL=ON
%else
_MOUNT_INSTALL=OFF
%endif


cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix} \
		-D_APPFW_FEATURE_DRM_ENABLE:BOOL=${_DRM_ENABLE} \
		-D_APPFW_FEATURE_EXPANSION_PKG_INSTALL:BOOL=${_EXPANSION_PKG_INSTALL} \
		-D_APPFW_FEATURE_DELTA_UPDATE:BOOL=${_DELTA_UPDATE} \
		-D_APPFW_FEATURE_MOUNT_INSTALL:BOOL=${_MOUNT_INSTALL}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}
cp LICENSE %{buildroot}/usr/share/license/%{name}-client
cp LICENSE %{buildroot}/usr/share/license/%{name}-installer

%post
/sbin/ldconfig

mkdir -p /usr/etc/package-manager/backend
mkdir -p /usr/etc/package-manager/backendlib
mkdir -p /usr/share/packages
mkdir -p /opt/share/packages
mkdir -p /usr/share/applications
mkdir -p /opt/share/applications

%post client
/sbin/ldconfig

%posttrans client
chsmack -a '_' /usr/etc/package-manager/pkg_path.conf

%postun client -p /sbin/ldconfig

%post installer -p /sbin/ldconfig

%postun installer -p /sbin/ldconfig

%files
%manifest pkgmgr.manifest
%defattr(-,root,root,-)
%{_includedir}/package-manager-debug.h
%{_includedir}/package-manager-internal.h
%{_includedir}/pkgmgr/comm_pkg_mgr_server.h
%{_includedir}/pkgmgr/comm_config.h
%exclude %{_includedir}/pkgmgr/comm_client.h
%exclude %{_includedir}/pkgmgr/comm_status_broadcast_server.h
/usr/share/license/%{name}

%files client
%manifest pkgmgr-client.manifest
%defattr(-,root,root,-)
%{_prefix}/etc/package-manager/pkg_path.conf
%{_libdir}/libpkgmgr-client.so.*
/usr/share/license/%{name}-client

%files client-devel
%defattr(-,root,root,-)
%{_includedir}/package-manager.h
%{_includedir}/package-manager-zone.h
%{_libdir}/pkgconfig/pkgmgr.pc
%{_libdir}/libpkgmgr-client.so

%files installer
%manifest pkgmgr-installer.manifest
%defattr(-,root,root,-)
%{_libdir}/libpkgmgr_installer.so.*
%{_libdir}/libpkgmgr_installer_status_broadcast_server.so.*
%{_libdir}/libpkgmgr_installer_client.so.*
%{_libdir}/libpkgmgr_installer_pkg_mgr_server.so.*
/usr/share/license/%{name}-installer

%files installer-devel
%defattr(-,root,root,-)
%{_includedir}/pkgmgr/pkgmgr_installer.h
%{_libdir}/pkgconfig/pkgmgr-installer-status-broadcast-server.pc
%{_libdir}/pkgconfig/pkgmgr-installer.pc
%{_libdir}/pkgconfig/pkgmgr-installer-client.pc
%{_libdir}/pkgconfig/pkgmgr-installer-pkg-mgr-server.pc
%{_libdir}/libpkgmgr_installer.so
%{_libdir}/libpkgmgr_installer_client.so
%{_libdir}/libpkgmgr_installer_status_broadcast_server.so
%{_libdir}/libpkgmgr_installer_pkg_mgr_server.so


%files types-devel
%defattr(-,root,root,-)
%{_includedir}/package-manager-types.h
%{_includedir}/package-manager-plugin.h
%{_libdir}/pkgconfig/pkgmgr-types.pc
