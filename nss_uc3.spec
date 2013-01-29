Summary: NSS modules used at UC3
Name: nss_uc3
Version: 24
Release: 1
License: MIT
URL: https://bitbucket.org/dgc/nss_uc3
Group: Foo/Bar
Source0: nss_uc3-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

BuildRequires: make, gcc
Provides: nss_identity = %{version}-%{release}, nss_filter = %{version}-%{release}

%description

nss_identity
============

  nss_identity provides a means of fabricating POSIX nameservice entries
  based upon information present in the request and (perhaps) elsewhere
  within the nsswitch framework, but without reference to an external
  source of authority.  This is primarily useful for fabricating
  identities: a 1:1 mapping of numeric IDs to predictably corresponding
  text representations.

nss_filter
==========

  nss_filter is a preliminary effort at an NSS library that authoritatively
  sources nothing, but can filter results from other libraries.  It is
  currently quite limited: it is capable of filtering only passwd, and it
  can only perform one type of filtering: replacing a '&' token with the
  user login ID (``pw_name``).  This is sufficient proof of concept and
  adequate to our current need, but it should be extended:

  * because it can be, and it is not complete;
  * because it only offers one type of filter that is hardcoded.

%prep
%setup -n nss_uc3-%{version}

%build
make all

%install
rm -rf $RPM_BUILD_ROOT
make install prefix=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc README
%doc doc/*.txt
/usr/share/man/man3/nss_identity.3.gz
/usr/share/man/man3/nss_filter.3.gz
/%{_lib}
#/lib64/libnss_identity.so.2
#/lib64/libnss_filter.so.2
