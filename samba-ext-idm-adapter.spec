Name:		samba-ext-idm-adapter
Version:	1
Release:	1%{?dist}
Summary:	Creates homes and changes Samba password hashes

Group:		Applications/System
License:	MIT
URL:		http://github.com/techlib/samba-ext-idm-adapter
Source0:	%{name}-%{version}.tar.gz

BuildRequires:	libldb-devel
BuildRequires:	libtalloc-devel

%description
Tool to create user home directories and symbolic links as well as
set Samba password hashes using libldb for the Midpoint IdM.


%prep
%setup -q


%build
make %{?_smp_mflags}


%install
make install DESTDIR=%{buildroot}


%files
%{_sbindir}/samba-ext-idm-adapter


%changelog
