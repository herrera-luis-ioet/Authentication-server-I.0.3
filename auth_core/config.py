"""
Configuration module for the Authentication Core Component.

This module re-exports the settings from the config package for easier access.
"""

from auth_core.config.settings import settings, get_settings

__all__ = ["settings", "get_settings"]