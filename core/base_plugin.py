from abc import ABC, abstractmethod
import importlib
import pkgutil
import plugins

class BasePlugin(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def run(self, target: str, ports: str = None) -> dict:
        pass

class PluginManager:
    def __init__(self):
        self.plugins = []
        self._load_plugins()

    def _load_plugins(self):
        """Dynamically load all plugins from the plugins package"""
        for _, name, _ in pkgutil.iter_modules(plugins.__path__):
            try:
                module = importlib.import_module(f'plugins.{name}')
                for attribute_name in dir(module):
                    attribute = getattr(module, attribute_name)
                    if (isinstance(attribute, type) and 
                        issubclass(attribute, BasePlugin) and 
                        attribute is not BasePlugin):
                        self.plugins.append(attribute())
            except Exception as e:
                print(f"Failed to load plugin {name}: {str(e)}")

    def get_plugins(self):
        return self.plugins
