%define name python-cb-fidelis-bridge
%define version 1.2
%define unmangled_version 1.2
%define release 1
%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}

Summary: Carbon Black Fidelis Bridge
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{unmangled_version}.tar.gz
License: MIT
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: x86_64
Vendor: Bit9
Url: http://www.bit9.com/

%description
UNKNOWN

%prep
%setup -n %{name}-%{unmangled_version}

%build
pyinstaller cb-fidelis-connector.spec

%pre
if [ -f "/etc/cb/integrations/carbonblack_fidelis_bridge/carbonblack_fidelis_bridge.conf" ]; then
    cp /etc/cb/integrations/carbonblack_fidelis_bridge/carbonblack_fidelis_bridge.conf /tmp/__bridge.conf.backup
fi

%install
python setup.py install_cb --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%post
#!/bin/sh

mkdir -p /usr/share/cb/integrations/fidelis/db
chkconfig --add cb-fidelis-bridge
chkconfig --level 345 cb-fidelis-bridge on

# not auto-starting because conf needs to be updated
#/etc/init.d/cb-fidelis-bridge start
if [ -f "/tmp/__bridge.conf.backup" ]; then
    mv /tmp/__bridge.conf.backup /etc/cb/integrations/carbonblack_fidelis_bridge/carbonblack_fidelis_bridge.conf
fi


%preun
#!/bin/sh

/etc/init.d/cb-fidelis-bridge stop

chkconfig --del cb-fidelis-bridge


%files -f INSTALLED_FILES
%defattr(-,root,root)

%config
/etc/cb/integrations/carbonblack_fidelis_bridge/carbonblack_fidelis_bridge.conf.template

%config(noreplace)
/etc/cb/integrations/carbonblack_fidelis_bridge/carbonblack_fidelis_bridge.conf

