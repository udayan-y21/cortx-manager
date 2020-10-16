# CORTX MESSAGE-BUS-SERVER.
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


message_bus_server_path = '/opt/seagate/cortx/message_bus_server/'

block_cipher = None

# Analysis
message_bus_server = Analysis([message_bus_server_path + 'server.py'],
             pathex=[],
             binaries=[],
             datas=[],
             hiddenimports=['gunicorn.glogging', 'gunicorn.workers.gthread'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)

# message_bus_server
message_bus_server_pyz = PYZ(message_bus_server.pure, message_bus_server.zipped_data,
             cipher=block_cipher)

message_bus_server_exe = EXE(message_bus_server_pyz,
          message_bus_server.scripts,
          [],
          exclude_binaries=True,
          name='message_bus_server',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          console=True)

coll = COLLECT(
               # Message bus server
               message_bus_server_exe,
               message_bus_server.binaries,
               message_bus_server.zipfiles,
               message_bus_server.datas,

               strip=False,
               upx=True,
               upx_exclude=[],
               name='lib')