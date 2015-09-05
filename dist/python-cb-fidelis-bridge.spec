%define name python-cb-fidelis-bridge
%define version 1.2.0.150904
%define unmangled_version 1.2.0.150904
%define release 1

Summary: Carbon Black Fidelis Bridge
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{unmangled_version}.tar.gz
License: Commercial
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: x86_64
Vendor: Carbon Black <support@carbonblack.com>
Requires: python-cbapi python-cb-integration >= 1.1.14210
Url: http://www.carbonblack.com/

%description
UNKNOWN

%prep
%setup -n %{name}-%{unmangled_version}

%build
python setup.py build

%install
python setup.py install -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%post
#!/bin/sh

chkconfig --add cb-fidelis-bridge
chkconfig --level 345 cb-fidelis-bridge on

# not auto-starting because conf needs to be updated
#/etc/init.d/cb-fidelis-bridge start


%preun
#!/bin/sh

/etc/init.d/cb-fidelis-bridge stop

chkconfig --del cb-fidelis-bridge


%files -f INSTALLED_FILES
%defattr(-,root,root)
%config(noreplace) /etc/cb/integrations/carbonblack_fidelis_bridge/carbonblack_fidelis_bridge.conf 
