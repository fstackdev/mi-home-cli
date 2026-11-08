"""Only fixed, credential-free error messages cross the CLI boundary."""


class MiHomeError(Exception):
    """A safe message that may be shown to the user."""


class AuthenticationError(MiHomeError):
    pass


class NetworkError(MiHomeError):
    pass


class RateLimitError(MiHomeError):
    pass


class ProtocolError(MiHomeError):
    pass


class RegionError(MiHomeError):
    pass


class StorageError(MiHomeError):
    pass
