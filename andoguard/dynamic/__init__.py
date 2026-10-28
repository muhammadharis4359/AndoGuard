"""Dynamic instrumentation, Frida hooks, and memory operations (Milestones 5-6)."""

from andoguard.adapters.frida_bridge import FridaBridge
from andoguard.dynamic.generator import (
    generate_java_class_hook,
    generate_java_method_hook,
    generate_native_hook,
)
from andoguard.dynamic.tracer import MethodTracer, generate_pattern_tracer_script

__all__ = [
    "FridaBridge",
    "generate_java_method_hook",
    "generate_java_class_hook",
    "generate_native_hook",
    "generate_pattern_tracer_script",
    "MethodTracer",
]
