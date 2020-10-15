# CORTX MESSAGE-BUS-SERVER
# Copyright (c) 2020 Seagate Technology LLC and/or its Affiliates
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
# For any questions about this software or licensing,
# please email opensource@seagate.com or cortx-questions@seagate.com.

Name: <RPM_NAME>
Version: %{version}
Release: %{dist}
Summary: Message Bus Server
License: Seagate Proprietary
URL: https://github.com/Seagate/cortx-manager
Source0: <PRODUCT>-message_bus_server-%{version}.tar.gz
%define debug_package %{nil}

%description
Message Bus Server

%prep
%setup -n message_bus_server
# Nothing to do here

%build

%install
mkdir -p ${RPM_BUILD_ROOT}<MESSAGE_BUS_SERVER_PATH>
cp -rp . ${RPM_BUILD_ROOT}<MESSAGE_BUS_SERVER_PATH>
exit 0

%post
MESSAGE_BUS_SERVER_DIR=<MESSAGE_BUS_SERVER_PATH>
CFG_DIR=$MESSAGE_BUS_SERVER_DIR/conf
cp -f $CFG_DIR/service/message_bus_server.service /etc/systemd/system/message_bus_server.service
exit 0

%preun
[ $1 -eq 1 ] && exit 0
systemctl disable message_bus_server
systemctl stop message_bus_server

%postun
[ $1 -eq 1 ] && exit 0
rm -f /etc/systemd/system/message_bus_server.service 2> /dev/null;
systemctl daemon-reload
exit 0

%clean

%files
# TODO - Verify permissions, user and groups for directory.
%defattr(-, root, root, -)
<MESSAGE_BUS_SERVER_PATH>/*

%changelog
* Thu Oct 15 2020 Shri Bhargav Metta <shri.metta@seagate.com> - 1.0.0
- Initial spec file