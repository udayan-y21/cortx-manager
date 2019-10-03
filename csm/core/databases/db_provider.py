from abc import ABC, abstractmethod
from pydoc import locate
from schematics import Model
from schematics.types import DictType, BaseType, StringType, ListType, ModelType
from typing import Type, Dict, List, Union
from csm.core.blogic.models import CsmModel
from csm.core.blogic.data_access.errors import MalformedConfigurationError
from csm.core.blogic.data_access.storage import IStorage, AbstractDbProvider


class IDatabaseDriver(ABC):
    """
    Interface for database drivers.
    Database drivers are supposed to be responsible for instantiating IStorage objects.
    """
    @abstractmethod
    async def get_storage(self, model, config: dict) -> IStorage:
        pass


class CachedDatabaseDriver(IDatabaseDriver, ABC):
    """
    Implementation of IDatabaseDriver that allows not to implement storage caching
    """
    def __init__(self):
        self.cache = {}

    async def get_storage(self, model, config: dict) -> IStorage:
        if model in self.cache:
            return self.cache[model]
        else:
            storage = await self.create_storage(model, config)
            self.cache[model] = storage
            return storage

    @abstractmethod
    async def create_storage(self, model, config) -> IStorage:
        pass


class DbDriverConfig(Model):
    """
    Database driver configuration description
    """
    import_path = StringType(required=True)
    config = BaseType(default={})  # driver-specific configuration


class DbModelConfig(Model):
    """
    Description of how a specific model is expected to be stored
    """
    import_path = StringType(required=True)
    driver = StringType(required=True)
    # TODO: Discuss: maybe better to use DictType?
    config = BaseType(default={})  # this configuration is db driver-specific


class DbConfig(Model):
    """
    Layout of full database configuration
    """
    drivers = DictType(ModelType(DbDriverConfig), str)
    models = ListType(ModelType(DbModelConfig))


class DbDriverProvider:
    """
    Helper class for database drivers management.
    It is responsible for instantiating database drivers depending on the configuration.
    """
    def __init__(self, driver_config: Dict[str, DbDriverConfig]):
        self.driver_config = driver_config
        self.instances = {}

    async def get_driver(self, key: str) -> IDatabaseDriver:
        """
        Returns a database driver instance depending on the string identifier of
        the driver that was passed as a part of configuration.

        :param key: Database driver key
        :returns: Database driver instance
        """
        if key in self.instances:
            return self.instances[key]
        else:
            ret = await self._create_driver(key)
            self.instances[key] = ret

            return ret

    async def _create_driver(self, key: str):
        if key not in self.driver_config:
            raise MalformedConfigurationError(f"No driver configuration for '{key}'")

        driver = locate(self.driver_config[key].import_path)
        if not driver:
            raise MalformedConfigurationError(f"Cannot import driver class for '{key}'")

        # TODO: consider adding some async drive initialization routine
        return driver(self.driver_config[key].config)


# TODO: class can't be inherited from IStorage
class AsyncStorageDecorator:

    def __init__(self, get_storage_future):
        self.get_storage_future = get_storage_future

    def __getattr__(self, attr_name):
        async def _proxy_call(*args, **kwargs):
            storage = await self.get_storage_future
            attr = storage.__getattribute__(attr_name)
            if callable(attr):
                # may be, first call the function and then check whether we need to await it
                return await attr(*args, **kwargs)
            else:
                return attr

        return _proxy_call


class DbStorageProvider(AbstractDbProvider):

    def __init__(self, driver_provider: DbDriverProvider, model_config: List[DbModelConfig]):
        self.driver_provider = driver_provider
        self.model_config = {}

        for model in model_config:
            model_class = locate(model.import_path)

            if not model_class:
                raise MalformedConfigurationError(f"Couldn't import '{model.import_path}'")

            if not issubclass(model_class, CsmModel):
                raise MalformedConfigurationError(f"'{model.import_path}'"
                                                  f" must be a subclass of CsmModel")

            self.model_config[model_class] = model

    def get_storage(self, model: Type[CsmModel]):
        return AsyncStorageDecorator(self._get_storage(model))

    async def _get_storage(self, model: Type[CsmModel]):
        if model not in self.model_config:
            raise MalformedConfigurationError(f"No configuration for {model}")

        model_config = self.model_config[model]  # type: DbModelConfig
        driver = await self.driver_provider.get_driver(model_config.driver)

        return await driver.get_storage(model, model_config.config)
