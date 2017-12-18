%define name python-cb-skyatp-connector
%define version 0.9
%define unmangled_version 0.9
%define release 0
%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}

Summary: Carbon Black Sky ATP Bridge
Name: %{name}
Version: %{version}
Release: %{release}
Source: %{name}-%{unmangled_version}.tar.gz
License: MIT
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: x86_64
Vendor: Carbon Black Inc.
Url: http://www.carbonblack.com/

%description
UNKNOWN

%prep
%setup -n %{name}-%{unmangled_version}

%build
pyinstaller cb-skyatp-connector.spec

%pre
if [ -f "/etc/cb/integrations/carbonblack-skyatp-connector/carbonblack-skyatp-connector.conf" ]; then
    cp /etc/cb/integrations/carbonblack-skyatp-connector/carbonblack-skyatp-connector.conf /tmp/__bridge.conf.backup
fi

%install
python setup.py install_cb --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%post
#!/bin/sh

mkdir -p /usr/share/cb/integrations/skyatp/db
chkconfig --add cb-skyatp-connector
chkconfig --level 345 cb-skyatp-connector on

# not auto-starting because conf needs to be updated
#/etc/init.d/cb-skyatp-connector start
if [ -f "/tmp/__bridge.conf.backup" ]; then
    mv /tmp/__bridge.conf.backup /etc/cb/integrations/carbonblack-skyatp-connector/carbonblack-skyatp-connector.conf
fi


%preun
#!/bin/sh

/etc/init.d/cb-skyatp-connector stop

chkconfig --del cb-skyatp-connector


%files -f INSTALLED_FILES
%defattr(-,root,root)

%config
/etc/cb/integrations/carbonblack-skyatp-connector/carbonblack-skyatp-connector.conf.template

