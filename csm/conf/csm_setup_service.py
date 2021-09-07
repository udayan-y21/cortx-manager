#!/usr/bin/env python3

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


from csm.common.errors import ResourceExist
from cortx.utils.security.cipher import Cipher, CipherInvalidToken
from cortx.utils.service.service_handler import Service
from csm.common.payload import Text, Yaml
from csm.conf.setup_util import Const, CsmSetupError, Setup_Util
import traceback
import os
import pwd
import crypt
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
    def __init__(self, config_url, service_name = None):
        self.config_url = config_url
        self.machine_id = Conf.machine_id
        self.service_name = service_name
        Conf.load(Const.CONSUMER_INDEX, self.config_url)
        Conf.load(const.CSM_GLOBAL_INDEX, const.CSM_CONF_URL)

    def post_install(self):
        self._prepare_and_validate_confstore_keys("post_install")
        self.validate_3rd_party_pkgs()
        self._set_deployment_mode()
        self._config_user()
        self._configure_system_auto_restart()
        self._configure_service_user()
        self._configure_rsyslog()
        return 0

    def prepare(self):
        self._prepare_and_validate_confstore_keys("prepare")
        self._set_deployment_mode()
        self._set_secret_string_for_decryption()
        self._set_cluster_id()
        self._set_db_host_addr()
        self._set_fqdn_for_nodeid()
        self._set_s3_ldap_credentials()
        self._set_password_to_csm_user()
        self.save_config()
        return 0

    def config(self):
        self._prepare_and_validate_confstore_keys("config")
        self._set_deployment_mode()
        self._logrotate()
        self._configure_cron()
        self._configure_uds_keys()
        self.save_config()
        return 0


    def init(self):

        return 0
    def reset(self):
        return 0
    def cleanup(self):
        return 0
    def pre_upgrade(self):
        return 0
    def post_upgrade(self):
        return 0
    def service(self):
        return 0

    def _prepare_and_validate_confstore_keys(self, phase: str):
        """ Perform validtions. Raises exceptions if validation fails """
        if phase == "post_install":
            self.conf_store_keys.update({
                "server_node_info_key":f"server_node>{self.machine._id}",
                "server_node_type_key":f"server_node>{self.machine._id}>type",
                "enclosure_id_key":f"server_node>{self.machine._id}>storage>enclosure_id",
                "csm_user_key":"cortx>software>csm>user"
                })
        elif phase == "prepare":
            self.conf_store_keys.update({
                "server_node_info_key":f"server_node>{self.machine._id}",
                "server_node_type_key":f"server_node>{self.machine._id}>type",
                "enclosure_id_key":f"server_node>{self.machine._id}>storage>enclosure_id",
                "node_hostname_key":f"server_node>{self.machine._id}>hostname",
                "data_nw_private_fqdn_key":f"server_node>{self.machine._id}>network>data>private_fqdn",
                "cluster_id_key":f"server_node>{self.machine._id}>cluster_id",
                "s3_ldap_secret_key":"cortx>software>openldap>sgiam>secret",
                "s3_ldap_user_key":"cortx>software>openldap>sgiam>user",
                "csm_secret_key":"cortx>software>csm>secret",
                "csm_user_key":"cortx>software>csm>user"
            })
        elif phase == "config":
            self.conf_store_keys.update({
                "server_node_info_key":f"server_node>{self.machine._id}",
                "server_node_type_key":f"server_node>{self.machine._id}>type",
                "enclosure_id_key":f"server_node>{self.machine._id}>storage>enclosure_id",
                "data_nw_public_fqdn_key":f"server_node>{self.machine._id}>network>data>public_fqdn",
                "cluster_id_key":f"server_node>{self.machine._id}>cluster_id",
                "csm_user_key":"cortx>software>csm>user"
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

        try:
            Setup_Util._validate_conf_store_keys(Const.CONSUMER_INDEX,
                                            list(self.conf_store_keys.values()))
        except VError as ve:
            Log.error(f"Key not found in Conf Store: {ve}")
            raise CsmSetupError(f"Key not found in Conf Store: {ve}")
        return 0

    def __get_setup_info(self):
        """
        Return Setup Info from Conf Store
        :return:
        """
        self._setup_info = {"node_type": "", "storeage_type": ""}
        self._setup_info["node_type"] = Conf.get(Const.CONSUMER_INDEX,
                                            self.conf_store_keys["server_node_type_key"])
        enclosure_id = Conf.get(Const.CONSUMER_INDEX, self.conf_store_keys["enclosure_id_key"])
        storage_type_key = f"storage_enclosure>{enclosure_id}>type"
        Setup_Util._validate_conf_store_keys(Const.CONSUMER_INDEX, [storage_type_key])
        self._setup_info["storeage_type"] = Conf.get(Const.CONSUMER_INDEX, storage_type_key)

    def _set_service_user(self):
        """
        This Method will set the username for service user to Self._user
        :return:
        """
        self._user = Conf.get(Const.CONSUMER_INDEX, self.conf_store_keys["csm_user_key"])

    def _set_deployment_mode(self):
        """
        This Method will set a deployment Mode according to env_type.
        :return:
        """
        self.__get_setup_info()
        self._set_service_user()
        if self._setup_info["node_type"] in ["VM", "virtual"]:
            Log.info("Running Csm Setup for VM Environment Mode.")
            self._is_env_vm = True

        if Conf.get(Const.CONSUMER_INDEX, "DEPLOYMENT>mode") == "dev":
            Log.info("Running Csm Setup for Dev Mode.")
            self._is_env_dev = True

    def validate_3rd_party_pkgs(self):
        try:
            Log.info("Validating dependent rpms")
            PkgV().validate("rpms",["elasticsearch-oss-7.10",
                                    "consul-1.9",
                                    "opendistroforelasticsearch-kibana-1.12",
                                    "cortx-csm_web"])
            Log.info("Valdating  3rd party Python Packages")
            PkgV().validate("pip3s", self.fetch_python_pkgs())
        except VError as ve:
            Log.error(f"Failed at package Validation: {ve}")
            raise CsmSetupError(f"Failed at package Validation: {ve}")

    def fetch_python_pkgs(self):
        try:
            pkgs_data = Text(Const.REQ_TXT_PATH).load()
            return {ele.split("==")[0]:ele.split("==")[1] for ele in pkgs_data.splitlines()}
        except Exception as e:
            Log.error(f"Failed to fetch python packages: {e}")
            raise CsmSetupError("Failed to fetch python packages")

    def _config_user(self, reset=False):
        """
        Check user already exist and create if not exist
        If reset true then delete user
        """
        if not Setup_Util._is_user_exist(self._user):
            Log.info("Creating CSM User without password.")
            Setup_Util._run_cmd((f"useradd -M {self._user}"))
            Log.info("Adding CSM User to Wheel Group.")
            Setup_Util._run_cmd(f"usermod -aG wheel {self._user}")
            Log.info("Enabling nologin for CSM user.")
            Setup_Util._run_cmd(f"usermod -s /sbin/nologin {self._user}")
            if not Setup_Util._is_user_exist(self._user):
                Log.error("Csm User Creation Failed.")
                raise CsmSetupError(f"Unable to create {self._user} user")
        else:
            Log.info(f"User {self._user} already exist")

        if Setup_Util._is_user_exist(self._user) and \
                                        Setup_Util._is_group_exist('haclient'):
            Log.info(f"Add Csm User: {self._user} to HA-Client Group.")
            Setup_Util._run_cmd(f"usermod -a -G haclient {self._user}")

    def _configure_system_auto_restart(self):
        """
        Check's System Installation Type an dUpdate the Service File
        Accordingly.
        :return: None
        """
        if not (Conf.get(Const.CONSUMER_INDEX,
                'systemd>csm>csm_agent>restart_on_failure') == 'true'):
            return None
        Log.info("Configuring System Auto restart")
        is_auto_restart_required = list()
        if self._setup_info:
            for each_key in self._setup_info:
                comparison_data = Const.EDGE_INSTALL_TYPE.get(each_key,
                                                              None)
                # Check Key Exists:
                if comparison_data is None:
                    Log.warn(f"Edge Installation missing key {each_key}")
                    continue
                if isinstance(comparison_data, list):
                    if self._setup_info[each_key] in comparison_data:
                        is_auto_restart_required.append(False)
                    else:
                        is_auto_restart_required.append(True)
                elif self._setup_info[each_key] == comparison_data:
                    is_auto_restart_required.append(False)
                else:
                    is_auto_restart_required.append(True)
        else:
            Log.warn("Setup info does not exist.")
            is_auto_restart_required.append(True)
        if any(is_auto_restart_required):
            Log.debug("Updating All setup file for Auto Restart on "
                      "Failure")
            Setup_Util._update_csm_files("#< RESTART_OPTION >",
                                       "Restart=on-failure")
            Setup_Util._run_cmd("systemctl daemon-reload")

    def _configure_service_user(self):
        """
        Configures the Service user in CSM service files.
        :return:
        """
        Setup_Util._update_csm_files("<USER>", self._user)

    def _configure_rsyslog(self):

        """
        Configure rsyslog
        """
        Log.info("Configuring rsyslog")
        os.makedirs(Const.RSYSLOG_DIR, exist_ok=True)
        if os.path.exists(Const.RSYSLOG_DIR):
            Setup_Util._run_cmd(f"cp -f {Const.SOURCE_RSYSLOG_PATH} {Const.RSYSLOG_DIR}")
            Log.info("Restarting rsyslog service")
            service_obj = Service('rsyslog.service')
            service_obj.restart()
        else:
            msg = f"rsyslog failed. {Const.RSYSLOG_DIR} directory missing."
            Log.error(msg)
            raise CsmSetupError(msg)

    def _set_secret_string_for_decryption(self):
        '''
        This will be the root of csm secret key
        eg: for "cortx>software>csm>secret" root is "cortx"
        '''
        Log.info("Set decryption keys for CSM and S3")
        Conf.set(Const.CSM_GLOBAL_INDEX, f"CSM>password_decryption_key",
                    self.conf_store_keys["csm_secret_key"].split('>')[0])
        Conf.set(Const.CSM_GLOBAL_INDEX, f"S3>password_decryption_key",
                    self.conf_store_keys["s3_ldap_secret_key"].split('>')[0])

    def _set_cluster_id(self):
        Log.info("Setting up cluster id")
        cluster_id = Conf.get(Const.CONSUMER_INDEX, self.conf_store_keys["cluster_id_key"])
        if not cluster_id:
            raise CsmSetupError("Failed to fetch cluster id")
        Conf.set(Const.CSM_GLOBAL_INDEX, "PROVISIONER>cluster_id", cluster_id)

    def _set_db_host_addr(self):
        """
        Sets database hosts address in CSM config.
        :return:
        """
        consul_host = self.__get_consul_info()
        es_host = self.__get_es_hosts_info()
        try:
            Conf.set(Const.DATABASE_INDEX, 'databases>es_db>config>hosts', es_host)
            Conf.set(Const.DATABASE_INDEX, 'databases>consul_db>config>hosts', consul_host)
        except Exception as e:
            Log.error(f'Unable to set host address: {e}')
            raise CsmSetupError(f'Unable to set host address: {e}')

    def __get_consul_info(self):
        """
        Obtains list of consul host address
        :return: list of ip where consule is running
        """
        Log.info("Fetching data N/W info.")
        data_nw_private_fqdn = Conf.get(Const.CONSUMER_INDEX,
                                self.conf_store_keys["data_nw_private_fqdn_key"])
        try:
            NetworkV().validate('connectivity', [data_nw_private_fqdn])
        except VError as e:
            Log.error(f"Network Validation failed.{e}")
            raise CsmSetupError(f"Network Validation failed.{e}")
        return [data_nw_private_fqdn]

    def __get_es_hosts_info(self):
    	"""
        Obtains list of elasticsearch hosts ip running in a cluster
    	:return: list of elasticsearch hosts ip running in a cluster
    	"""
    	Log.info("Fetching data N/W info.")
    	server_node_info = Conf.get(Const.CONSUMER_INDEX, "server_node_info_key")
    	data_nw_private_fqdn_list = []
    	for machine_id, node_data in server_node_info.items():
            data_nw_private_fqdn_list.append(node_data["network"]["data"]["private_fqdn"])
    	try:
            NetworkV().validate('connectivity', data_nw_private_fqdn_list)
    	except VError as e:
            Log.error(f"Network Validation failed.{e}")
            raise CsmSetupError(f"Network Validation failed.{e}")
    	return data_nw_private_fqdn_list

    def _set_s3_ldap_credentials(self):
                # read username's and password's for S3 and RMQ
        Log.info("Storing s3 credentials")
        open_ldap_user = Conf.get(Const.CONSUMER_INDEX,
                                     self.conf_store_keys["s3_ldap_user_key"])
        open_ldap_secret = Conf.get(Const.CONSUMER_INDEX,
                                     self.conf_store_keys["s3_ldap_secret_key"])
        # Edit Current Config File.
        if open_ldap_user and open_ldap_secret:
            Log.info("Open-Ldap Credentials Copied to CSM Configuration.")
            Conf.set(Const.CSM_GLOBAL_INDEX, f"S3>ldap_login",open_ldap_user)
            Conf.set(Const.CSM_GLOBAL_INDEX, f"S3>ldap_login",open_ldap_secret)

    def _set_password_to_csm_user(self):
        if not Setup_Util._is_user_exist():
            raise CsmSetupError(f"{self._user} not created on system.")
        Log.info("Fetch decrypted password.")
        _password = self.__fetch_csm_user_password(decrypt=True)
        if not _password:
            Log.error("CSM Password Not Available.")
            raise CsmSetupError("CSM Password Not Available.")
        _password = crypt.crypt(_password, "22")
        Setup_Util._run_cmd(f"usermod -p {_password} {self._user}")
        self.__store_encrypted_password()

    def __fetch_csm_user_password(self, decrypt=False):
        """
        This Method Fetches the Password for CSM User from Provisioner.
        :param decrypt:
        :return:
        """
        csm_user_pass = None
        if self._is_env_dev:
            decrypt = False
        Log.info("Fetching CSM User Password from Conf Store.")
        csm_user_pass = Conf.get(Const.CONSUMER_INDEX,
                                 self.conf_store_keys["csm_secret_key"])
        if decrypt and csm_user_pass:
            Log.info("Decrypting CSM Password.")
            try:
                cluster_id = Conf.get(Const.CONSUMER_INDEX,
                                         self.conf_store_keys["cluster_id_key"])
                cipher_key = Cipher.generate_key(cluster_id,
                                                Conf.get(Const.CSM_GLOBAL_INDEX,
                                                "CSM>password_decryption_key"))
            except KvError as error:
                Log.error(f"Failed to Fetch Cluster Id. {error}")
                return None
            except Exception as e:
                Log.error(f"{e}")
                return None
            try:
                decrypted_value = Cipher.decrypt(cipher_key,
                                                 csm_user_pass.encode("utf-8"))
                return decrypted_value.decode("utf-8")
            except CipherInvalidToken as error:
                Log.error(f"Decryption for CSM Failed. {error}")
                raise CipherInvalidToken(f"Decryption for CSM Failed. {error}")
        return csm_user_pass

    def _set_fqdn_for_nodeid(self):
        Log.info("Setting hostname to server node name")
        server_node_info = Conf.get(Const.CONSUMER_INDEX, "server_node_info_key")
        Log.debug(f"Server node information: {server_node_info}")
        for machine_id, node_data in server_node_info.items():
            hostname = node_data.get("hostname", "name")
            node_name = node_data.get("name")
            Conf.set(Const.CSM_GLOBAL_INDEX, f"MAINTENANCE>{node_name}", hostname)

    def __store_encrypted_password(self):
        """
        :return:
        """
        _paswd = self.__fetch_csm_user_password()
        if not _paswd:
            raise CsmSetupError("CSM Password Not Found.")

        Log.info("CSM Credentials Copied to CSM Configuration.")
        Conf.set(Const.CSM_GLOBAL_INDEX, f"CSM>password",_paswd)
        Conf.set(Const.CSM_GLOBAL_INDEX, f"PROVISIONER>password",_paswd)
        Conf.set(Const.CSM_GLOBAL_INDEX, f"CSM>username",self._user)
        Conf.set(Const.CSM_GLOBAL_INDEX, f"PROVISIONER>username",self._user)

    def _logrotate(self):
        """
        Configure logrotate
        """
        Log.info("Configuring logrotate.")
        if not os.path.exists(Const.LOGROTATE_DIR):
            Setup_Util._run_cmd(f"mkdir -p {Const.LOGROTATE_DIR}")

        if os.path.exists(Const.LOGROTATE_DIR):
            Setup_Util._run_cmd(f"cp -f {Const.SOURCE_LOGROTATE_PATH} " \
                                    f"{Const.LOGROTATE_DIR}/csm_agent_log.conf")
            if (self._setup_info and self._setup_info["storage_type"] == "virtual"):
                sed_script = f's/\\(.*rotate\\s\\+\\)[0-9]\\+/\\1{Const.LOGROTATE_AMOUNT_VIRTUAL}/'
                sed_cmd = f"sed -i -e {sed_script} " \
                                    f"{Const.LOGROTATE_DIR}/csm_agent_log.conf"
                Setup_Util._run_cmd(sed_cmd)
            Setup_Util._run_cmd(f"chmod 644 {Const.LOGROTATE_DIR}/csm_agent_log.conf")
        else:
            err_msg = f"logrotate failed. {Const.LOGROTATE_DIR} dir missing."
            Log.error(err_msg)
            raise CsmSetupError(err_msg)

    def _configure_cron(self):
        """
        Configure common rsyslog and logrotate
        Also cleanup statsd
        """
        if os.path.exists(Const.CRON_DIR):
            Setup_Util._run_cmd(f"cp -f {Const.SOURCE_CRON_PATH} {Const.DEST_CRON_PATH}")
            if self._setup_info and self._setup_info["storage_type"] == "virtual":
                sed_script = f'\
                    s/\\(.*es_cleanup.*-d\\s\\+\\)[0-9]\\+/\\1{Const.ES_CLEANUP_PERIOD_VIRTUAL}/'
                sed_cmd = f"sed -i -e {sed_script} {Const.DEST_CRON_PATH}"
                Setup_Util._run_cmd(sed_cmd)
        else:
            raise CsmSetupError(f"cron failed. {Const.CRON_DIR} dir missing.")

    def __fetch_management_ip(self):
        cluster_id = Conf.get(Const.CONSUMER_INDEX, self.conf_store_keys["cluster_id_key"])
        virtual_host_key = f"cluster>{cluster_id}>network>management>virtual_host"
        self._validate_conf_store_keys(Const.CONSUMER_INDEX,[virtual_host_key])
        virtual_host = Conf.get(Const.CONSUMER_INDEX, virtual_host_key)
        Log.info(f"Fetch Virtual host: {virtual_host}")
        return virtual_host

    def _configure_uds_keys(self):
        Log.info("Configuring UDS keys")
        virtual_host = self.__fetch_management_ip()
        data_nw_public_fqdn = Conf.get(Const.CONSUMER_INDEX, self.conf_store_keys["data_nw_public_fqdn_key"])
        Log.debug(f"Validating connectivity for data_nw_public_fqdn:{data_nw_public_fqdn}")
        try:
            NetworkV().validate('connectivity', [data_nw_public_fqdn])
        except Exception as e:
            Log.error(f"Network Validation failed. {e}")
            raise CsmSetupError("Network Validation failed.")
        Log.info(f"Set virtual_host:{virtual_host}, data_nw_public_fqdn:{data_nw_public_fqdn}"\
                                                        " to csm uds config")
        Conf.set(Const.CSM_GLOBAL_INDEX, f"PROVISIONER>virtual_host", virtual_host)
        Conf.set(Const.CSM_GLOBAL_INDEX, f"PROVISIONER>node_public_data_domain_name",
                                                         data_nw_public_fqdn)

    def _config_user_permission_set(self, crt, key):
        """
        Set User Permission
        """
        self._set_service_user()
        Log.info("Set User Permission")
        log_path = Conf.get(Const.CSM_GLOBAL_INDEX, "Log>log_path")
        os.makedirs(Const.CSM_PIDFILE_PATH, exist_ok=True)
        os.makedirs(log_path, exist_ok=True)
        os.makedirs(Const.PROVISIONER_LOG_FILE_PATH, exist_ok=True)
        os.makedirs(Const.CSM_TMP_FILE_CACHE_DIR, exist_ok=True)
        Setup_Util._run_cmd(f"setfacl -R -m u:{self._user}:rwx {Const.CSM_BASE_PATH}")
        Setup_Util._run_cmd((f"setfacl -R -m u:{self._user}:rwx "
                        f"{Const.CSM_TMP_FILE_CACHE_DIR}"))
        Setup_Util._run_cmd(f"setfacl -R -m u:{self._user}:rwx {log_path}")
        Setup_Util._run_cmd(f"setfacl -R -m u:{self._user}:rwx {Const.CSM_CONF_PATH}")
        Setup_Util._run_cmd(f"setfacl -R -m u:{self._user}:rwx {Const.CSM_PIDFILE_PATH}")
        Setup_Util._run_cmd(f"setfacl -R -m u:{self._user}:rwx {Const.PROVISIONER_LOG_FILE_PATH}")
        crt = Conf.get(Const.CSM_GLOBAL_INDEX, "HTTPS>certificate_path")
        key = Conf.get(Const.CSM_GLOBAL_INDEX, "HTTPS>private_key_path")
        if os.path.exists(crt):
            Setup_Util._run_cmd(f"setfacl -m u:{self._user}:rwx {crt}")
        if os.path.exists(key):
            Setup_Util._run_cmd(f"setfacl -m u:{self._user}:rwx {key}")
        Setup_Util._run_cmd("chmod +x /opt/seagate/cortx/csm/scripts/cortxha_shutdown_cron.sh")


    def save_config(self):
        """
        This Function Creates the CSM Conf File on Required Location.
        :return:
        """

        Log.info("Creating CSM Conf File on Required Location.")
        if self._is_env_dev:
            Conf.set(Const.CSM_GLOBAL_INDEX, "DEPLOYMENT>mode", "dev")
        Conf.save(Const.CSM_GLOBAL_INDEX)
        Conf.save(Const.DATABASE_INDEX)


    async def _create_cluster_admin(self, force_action=False):
        '''
        Create Cluster admin using CSM User managment.
        Username, Password, Email will be obtaineed from Confstore
        '''
        from csm.core.services.users import CsmUserService, UserManager
        from cortx.utils.data.db.db_provider import DataBaseProvider, GeneralConfig
        from csm.core.controllers.validators import PasswordValidator, UserNameValidator
        # TODO confstore keys can be changed.
        Log.info("Creating cluster admin account")
        cluster_admin_user = Conf.get(Const.CONSUMER_INDEX,
                                    "cortx>software>cluster_credential>username",
                                    Const.DEFAULT_CLUSTER_ADMIN_USER)
        cluster_admin_secret = Conf.get(Const.CONSUMER_INDEX,
                                    "cortx>software>cluster_credential>secret",
                                    Const.DEFAULT_CLUSTER_ADMIN_PASS)
        cluster_admin_emailid = Conf.get(Const.CONSUMER_INDEX,
                                    "cortx>software>cluster_credential>emailid",
                                    Const.DEFAULT_CLUSTER_ADMIN_EMAIL)

        UserNameValidator()(cluster_admin_user)
        PasswordValidator()(cluster_admin_secret)

        conf = GeneralConfig(Yaml(f"{self.config_path}/{const.DB_CONF_FILE_NAME}").load())
        db = DataBaseProvider(conf)
        usr_mngr = UserManager(db)
        usr_service = CsmUserService(usr_mngr)
        if (not force_action) and \
            (await usr_service.validate_cluster_admin_create(cluster_admin_user)):
            Log.console("WARNING: Cortx cluster admin already created.\n"
                        "Please use '-f' option to create admin user forcefully.")
            return None

        if force_action and await usr_mngr.get(cluster_admin_user):
            Log.info(f"Removing current user: {cluster_admin_user}")
            await usr_mngr.delete(cluster_admin_user)

        Log.info(f"Creating cluster admin: {cluster_admin_user}")
        try:
            await usr_service.create_cluster_admin(cluster_admin_user,
                                                cluster_admin_secret,
                                                cluster_admin_emailid)
        except ResourceExist as ex:
            Log.error(f"Cluster admin already exists: {cluster_admin_user}")
