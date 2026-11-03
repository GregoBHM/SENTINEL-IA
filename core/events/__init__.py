"""Stable, language-neutral scan events and client-facing presentation."""
from core.events.catalog import ClientMessage, make_event, present_event

__all__ = ["ClientMessage", "make_event", "present_event"]
