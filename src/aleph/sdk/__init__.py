from importlib.metadata import PackageNotFoundError, distribution

from aleph.sdk.client import AlephHttpClient, AuthenticatedAlephHttpClient

try:
    # Change here if project is renamed and does not equal the package name
    dist_name = "aleph-sdk-python"
    __version__ = distribution(dist_name).version
except PackageNotFoundError:
    __version__ = "unknown"
finally:
    del distribution, PackageNotFoundError

__all__ = ["AlephHttpClient", "AuthenticatedAlephHttpClient"]


def __getattr__(name):
    if name == "AlephClient":
        raise ImportError(
            "AlephClient has been turned into an abstract class. Please use `AlephHttpClient` instead."
        )
    elif name == "AuthenticatedAlephClient":
        raise ImportError(
            "AuthenticatedAlephClient has been turned into an abstract class. Please use `AuthenticatedAlephHttpClient` instead."
        )
    elif name == "synchronous":
        raise ImportError(
            "The 'aleph.sdk.synchronous' type is deprecated and has been removed from the aleph SDK. Please use `aleph.sdk.client.AlephHttpClient` instead."
        )
    elif name == "asynchronous":
        raise ImportError(
            "The 'aleph.sdk.asynchronous' type is deprecated and has been removed from the aleph SDK. Please use `aleph.sdk.client.AlephHttpClient` instead."
        )
