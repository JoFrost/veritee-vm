__all__ = ["Deployer"]


def __getattr__(name):
    if name == "Deployer":
        from .cli import Deployer

        return Deployer
    raise AttributeError(name)
