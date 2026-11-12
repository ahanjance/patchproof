"""Exceptions shared by the PatchProof modules."""


class PatchProofError(Exception):
    """Base class for errors that should end a run with exit code 30."""


class ConfigError(PatchProofError):
    """The TOML configuration is missing, malformed or references missing files."""


class RepoError(PatchProofError):
    """The target repository or a git operation is unusable."""
