"""Hook template generation for Java and native function interception."""

def generate_java_method_hook(
    class_name: str,
    method_name: str,
    dump_backtrace: bool = True,
    custom_return: str | None = None,
) -> str:
    """Generate typed Frida JavaScript hook for a target Java method."""
    clean_cls = class_name.strip("L;").replace("/", ".")
    bt_code = """
        var Log = Java.use("android.util.Log");
        var Exception = Java.use("java.lang.Exception");
        var stack = Log.getStackTraceString(Exception.$new());
    """ if dump_backtrace else 'var stack = "";'

    return_override = f"return {custom_return};" if custom_return is not None else "return res;"

    script = f"""// AndoGuard Auto-Generated Hook: {clean_cls}.{method_name}
Java.perform(function() {{
    var targetClass = Java.use("{clean_cls}");
    var overloads = targetClass["{method_name}"].overloads;

    overloads.forEach(function(overload) {{
        overload.implementation = function() {{
            var argsArray = [];
            for (var i = 0; i < arguments.length; i++) {{
                argsArray.push(arguments[i] !== null ? arguments[i].toString() : "null");
            }}

            {bt_code}

            send({{
                event_type: "call",
                class_name: "{clean_cls}",
                method_name: "{method_name}",
                args: argsArray,
                backtrace: stack
            }});

            var res = overload.apply(this, arguments);

            send({{
                event_type: "return",
                class_name: "{clean_cls}",
                method_name: "{method_name}",
                return_val: res !== null && res !== undefined ? res.toString() : "void/null"
            }});

            {return_override}
        }};
    }});
}});
"""
    return script


def generate_java_class_hook(class_name: str) -> str:
    """Generate hook for all declared methods of a target class."""
    clean_cls = class_name.strip("L;").replace("/", ".")
    return f"""// AndoGuard Class Tracer: {clean_cls}
Java.perform(function() {{
    var targetClass = Java.use("{clean_cls}");
    var methods = targetClass.class.getDeclaredMethods();

    methods.forEach(function(m) {{
        var mName = m.getName();
        if (targetClass[mName]) {{
            try {{
                targetClass[mName].overloads.forEach(function(overload) {{
                    overload.implementation = function() {{
                        var args = [];
                        for (var i = 0; i < arguments.length; i++) {{
                            args.push(arguments[i] !== null ? arguments[i].toString() : "null");
                        }}
                        send({{
                            event_type: "call",
                            class_name: "{clean_cls}",
                            method_name: mName,
                            args: args
                        }});
                        var res = overload.apply(this, arguments);
                        return res;
                    }};
                }});
            }} catch(err) {{}}
        }}
    }});
}});
"""


def generate_native_hook(function_name: str, library_name: str | None = None) -> str:
    """Generate Interceptor.attach hook for native C/C++ exported function."""
    lib_lookup = f'"{library_name}"' if library_name else "null"
    return f"""// AndoGuard Native Hook: {function_name} ({library_name or 'any module'})
var targetPtr = Module.findExportByName({lib_lookup}, "{function_name}");
if (targetPtr) {{
    Interceptor.attach(targetPtr, {{
        onEnter: function(args) {{
            send({{
                event_type: "native_enter",
                symbol: "{function_name}",
                arg0: args[0] ? args[0].toString() : "0x0",
                arg1: args[1] ? args[1].toString() : "0x0"
            }});
        }},
        onLeave: function(retval) {{
            send({{
                event_type: "native_leave",
                symbol: "{function_name}",
                retval: retval.toString()
            }});
        }}
    }});
}} else {{
    send({{ event_type: "error", message: "Symbol '{function_name}' not found." }});
}}
"""
