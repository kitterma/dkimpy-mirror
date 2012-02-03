%define __python python2.6
%define pythonbase python26

Summary: Python DKIM library
Name: %{pythonbase}-pydkim
Version: 0.5.1
Release: 1
Source0: http://hewgill.com/pydkim/pydkim-%{version}.tar.bz2
License: BSD-like
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: noarch
Vendor: Greg Hewgill <greg@hewgill.com>
Packager: Stuart D. Gathman <stuart@bmsi.com>
Url: http://hewgill.com/pydkim/
BuildRequires: %{pythonbase}-devel
Requires: %{pythonbase} %{pythonbase}-pydns

%description
Python DKIM library

%prep
%setup -n pydkim-%{version}

%build
%{__python} setup.py build

%install
%{__python} setup.py install --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES
sed -i -e'/man1/d' INSTALLED_FILES
#grep '\.pyc$' INSTALLED_FILE | sed -e's/c$/o/' >>INSTALLED_FILES
mkdir -p ${RPM_BUILD_ROOT}%{_mandir}/man1
cp -p man/*.1 ${RPM_BUILD_ROOT}%{_mandir}/man1

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%defattr(-,root,root)
%doc ChangeLog README LICENSE TODO
%{_mandir}/man1/dkimsign.1.gz
%{_mandir}/man1/dkimverify.1.gz
/usr/lib/%{__python}/site-packages/dkim/__main__.pyo

%changelog
* Fri Feb 03 2012 Stuart Gathman <stuart@bmsi.com> 0.5.1-1
- performance patch from https://launchpad.net/~petri Petri Lehtinen
- save parsed signatures in DKIM object
- do not require DNS/dnspython for signing

* Wed Oct 26 2011 Stuart Gathman <stuart@bmsi.com> 0.5-1
- raise KeyFormatError when missing required key parts in DNS
- test fail on extra headers in message
- test case for handling of multiple from
- do not sign all headers by default
- option to verify signatures other than first

* Wed Jun 15 2011 Stuart Gathman <stuart@bmsi.com> 0.4.1-1
- fix except clauses for python3
- Add test case for <https://launchpad.net/bugs/587783>
- add back dkim.Relaxed and dkim.Simple constants

* Tue Jun 14 2011 Stuart Gathman <stuart@bmsi.com> 0.4-1
- class DKIM API

* Mon Mar 07 2011 Stuart Gathman <stuart@bmsi.com> 0.3-2
- man pages

* Mon Mar 07 2011 Stuart Gathman <stuart@bmsi.com> 0.3-1
- Python 2.6
- Use pydns

