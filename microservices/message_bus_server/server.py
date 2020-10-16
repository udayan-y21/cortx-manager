#!/usr/bin/env python3

# CORTX MESSAGE-BUS-SERVER: server.py
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


from gunicorn.app.base import BaseApplication
from cortx.utils.schema.conf import Conf
from message_bus_server.app import message_bus_server_app
from message_bus_server.common.const import BaseConstants


class MessageBusServer(BaseApplication):

    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super().__init__()

    def load_config(self):
        config = {key: value for key, value in self.options.items()
                  if key in self.cfg.settings and value is not None}
        for key, value in config.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        return self.application


if __name__ == "__main__":
    options = {
        'bind': '%s:%s' % (Conf.get(BaseConstants.MSG_BUS_CONFIG_INDEX, "REST_SERVER.hostname"),
                           Conf.get(BaseConstants.MSG_BUS_CONFIG_INDEX, "REST_SERVER.port")),
        'workers': 1,
        'threads': 50
    }
    MessageBusServer(message_bus_server_app, options).run()
