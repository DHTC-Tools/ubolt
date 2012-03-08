Summary: a PAM module for automatic, dynamic account provisioning
Name: pam_provision
Version: 20
Release: 1
License: MIT
URL: https://bitbucket.org/dgc/pam_provision
Group: Foo/Bar
%define hg_rev 7abe9fe4b45d
Source0: https://bitbucket.org/dgc/pam_provision/get/%{hg_rev}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

BuildRequires: make, gcc
Provides: pam_provision = %{version}-%{release}

%description
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
%setup -n dgc-pam_provision-%{hg_rev}

%build
make all

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{_lib}/security
cp pam_provision.so $RPM_BUILD_ROOT/%{_lib}/security

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc LICENSE README
%doc provision.py
/%{_lib}/security/pam_provision.so
