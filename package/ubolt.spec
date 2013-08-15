Summary: Bolt-on identity management tools
Name: ubolt
Version: 61
Release: 1
License: MIT
URL: https://bitbucket.org/dgc/ubolt
Group: Foo/Bar
%define hg_rev tip
Source0: https://bitbucket.org/dgc/ubolt/get/%{hg_rev}.tar.gz
Source1: ubolt-findrequires.sh
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

# We must disable depends generation because otherwise RPM won't allow
# us to use glibc private symbols.  (We depend on glibc privates for
# our whole principle of operation, though.)  So we set up filtering.  See:
# https://fedoraproject.org/wiki/PackagingDrafts/FilteringAutomaticDependencies
%define    _use_internal_dependency_generator 0
%define    __find_requires %{SOURCE1}

BuildRequires: make, gcc
Provides: nss_identity = %{version}-%{release}, nss_filter = %{version}-%{release}, pam_provision = %{version}-%{release}

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

pam_provision
=============

  pam_provision.so is a PAM module to assist in automatic account
  provisioning.  It assumes that some kind of functioning POSIX account
  information is available through the name service switch: nss_files,
  nss_ldap, whatever.  If you can provide the account information,
  pam_provision can do whatever is necessary on the local system to
  make the account function.  This could be as minor as creating a home
  directory, or it could involve other elements of session management.
  Pam_provision's only job is to call the program you tell it to.  This
  provisioner program can be a shell script or a program in any other
  language.  An example provisioner written in Python is included with
  this distribution.

%prep
%setup -n dgc-ubolt-%{hg_rev}

%build
make all

%install
rm -rf $RPM_BUILD_ROOT
make install prefix=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc LICENSE README
%doc doc/*.txt
%doc provision.py
/usr/share/man/man3/nss_identity.3.gz
/usr/share/man/man3/nss_filter.3.gz
/%{_lib}
