#!/bin/env python3

# Copyright (c) 2021 Seagate Technology LLC and/or its Affiliates
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


from csm.conf.setup_util import Const, Setup_Util
import traceback
import os
import pwd
from cortx.utils.log import Log
from cortx.utils.conf_store import Conf
from cortx.utils.kv_store.error import KvError
from cortx.utils.process import SimpleProcess
from cortx.utils.validator.error import VError
from cortx.utils.validator.v_pkg import PkgV
from cortx.utils.validator.v_confkeys import ConfKeysV
from cortx.utils.validator.v_network import NetworkV
from cortx.utils.validator.v_path import PathV
from datetime import datetime

class Csm:
    def __init__(self, arg):
        pass

    def post_install(self):
        pass
    def prepare(self):
        pass
    def config(self):
        pass
    def init(self):
        pass
    def reset(self):
        pass
    def cleanup(self):
        pass
    def pre_upgrade(self):
        pass
    def post_upgrade(self):
        pass
    def service(self):
        pass

    def _prepare_and_validate_confstore_keys(self, phase: str):
        """ Perform validtions. Raises exceptions if validation fails """
        if phase == "post_install":
            self.conf_store_keys.update({
                })
        elif phase == "prepare":
            self.conf_store_keys.update({
            })
        elif phase == "config":
            self.conf_store_keys.update({
            })
        elif phase == "init":
            self.conf_store_keys.update({
            })
        elif phase == "post_upgrade":
            self.conf_store_keys.update({
            })
        elif phase == "pre_upgrade":
            self.conf_store_keys.update({
            })
        elif phase == "cleanup":
            self.conf_store_keys.update({
            })
        elif phase == "reset":
            self.conf_store_keys.update({
            })

        Setup_Util._validate_conf_store_keys(Const.CONSUMER_INDEX,
                                            list(self.conf_store_keys.values()))
        return 0
