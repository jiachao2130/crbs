Name:           hello
Version:        1.0
Release:        1%{?dist}
Summary:        Minimal test package for CRBS

License:        MIT
Source0:        hello.c

BuildRequires:  gcc
BuildRequires:  make

%description
A minimal C program for CRBS integration testing.

%prep
mkdir -p hello-1.0
cp %{SOURCE0} hello-1.0/

%build
cd hello-1.0
gcc -o hello hello.c

%install
mkdir -p %{buildroot}/usr/bin
cp hello-1.0/hello %{buildroot}/usr/bin/

%files
/usr/bin/hello

%changelog
* Fri Jun 05 2026 CRBS Test <test@example.com> - 1.0-1
- Initial package for integration testing
