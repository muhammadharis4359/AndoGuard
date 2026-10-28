"""Dynamic method tracer and event streaming."""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from andoguard.models import TraceEvent


def generate_pattern_tracer_script(pattern: str) -> str:
    """Generate Frida script that dynamically discovers and hooks classes matching pattern."""
    # Pattern format e.g. "com.example.*" or "com.example.MainActivity!on*"
    cls_pat = pattern
    meth_pat = "*"
    if "!" in pattern:
        cls_pat, meth_pat = pattern.split("!", 1)
    elif "#" in pattern:
        cls_pat, meth_pat = pattern.split("#", 1)

    return f"""// AndoGuard Pattern Tracer: {pattern}
Java.perform(function() {{
    var classPattern = "{cls_pat}";
    var methodPattern = "{meth_pat}";

    function matchWildcard(str, rule) {{
        var escapeRegex = function(s) {{ return s.replace(/([.*+?^=!:${{}}()|\\[\\]\\/\\\\])/g, "\\\\$1"); }};
        return new RegExp("^" + rule.split("*").map(escapeRegex).join(".*") + "$").test(str);
    }}

    Java.enumerateLoadedClasses({{
        onMatch: function(className) {{
            if (matchWildcard(className, classPattern)) {{
                try {{
                    var cls = Java.use(className);
                    var methods = cls.class.getDeclaredMethods();
                    methods.forEach(function(m) {{
                        var mName = m.getName();
                        if (matchWildcard(mName, methodPattern) && cls[mName]) {{
                            try {{
                                cls[mName].overloads.forEach(function(overload) {{
                                    overload.implementation = function() {{
                                        var argsList = [];
                                        for (var i = 0; i < arguments.length; i++) {{
                                            argsList.push(arguments[i] !== null ? arguments[i].toString() : "null");
                                        }}
                                        send({{
                                            event_type: "trace_call",
                                            class_name: className,
                                            method_name: mName,
                                            args: argsList
                                        }});
                                        var res = overload.apply(this, arguments);
                                        send({{
                                            event_type: "trace_return",
                                            class_name: className,
                                            method_name: mName,
                                            return_val: res !== null && res !== undefined ? res.toString() : "void/null"
                                        }});
                                        return res;
                                    }};
                                }});
                            }} catch(innerErr) {{}}
                        }}
                    }});
                }} catch(err) {{}}
            }}
        }},
        onComplete: function() {{
            send({{ event_type: "tracer_ready", pattern: "{pattern}" }});
        }}
    }});
}});
"""


class MethodTracer:
    """Collects and coordinates runtime trace events."""

    def __init__(self, on_event: Callable[[TraceEvent], None] | None = None) -> None:
        self.on_event = on_event
        self.events: list[TraceEvent] = []

    def handle_message(self, message: dict[str, Any], data: Any = None) -> None:
        """Process Frida JSON message payload and construct TraceEvent."""
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if isinstance(payload, dict):
                ev_type = payload.get("event_type", "call")
                cls_name = payload.get("class_name", "")
                meth_name = payload.get("method_name", "")
                args = payload.get("args", [])
                ret_val = payload.get("return_val")

                event = TraceEvent(
                    timestamp=datetime.now(UTC).isoformat(),
                    event_type=ev_type,
                    class_name=cls_name,
                    method_name=meth_name,
                    args=[str(a) for a in args],
                    return_val=str(ret_val) if ret_val is not None else None,
                )
                self.events.append(event)
                if self.on_event:
                    self.on_event(event)
