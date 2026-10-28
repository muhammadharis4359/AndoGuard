"""Control Flow Graph (CFG) generation and DOT rendering."""

from typing import Any

from andoguard.models import BasicBlockInfo, ControlFlowGraph


def build_cfg_from_basic_blocks(
    method_name: str, basic_blocks: list[Any]
) -> ControlFlowGraph:
    """Construct ControlFlowGraph and DOT representation from Androguard BasicBlocks."""
    blocks: list[BasicBlockInfo] = []
    dot_lines: list[str] = [
        f'digraph "CFG for {method_name}" {{',
        '  node [shape=box, fontname="Courier", style="filled", fillcolor="#f8f9fa"];',
        '  edge [color="#495057", fontname="Courier"];',
    ]

    for bb in basic_blocks:
        bb_name = getattr(bb, "name", f"block_{getattr(bb, 'start', 0)}")
        start_off = getattr(bb, "start", 0)
        end_off = getattr(bb, "end", 0)

        ins_list: list[str] = []
        if hasattr(bb, "get_instructions"):
            try:
                for ins in bb.get_instructions():
                    ins_list.append(f"{ins.get_name()} {ins.get_output()}")
            except Exception:
                pass

        child_names: list[str] = []
        if hasattr(bb, "childs"):
            try:
                for child_entry in bb.childs:
                    # child_entry can be a tuple (offset, branch_type, target_bb) or target_bb directly
                    target_bb = (
                        child_entry[2]
                        if isinstance(child_entry, (tuple, list)) and len(child_entry) >= 3
                        else child_entry
                    )
                    c_name = getattr(
                        target_bb, "name", f"block_{getattr(target_bb, 'start', 0)}"
                    )
                    child_names.append(c_name)
                    dot_lines.append(f'  "{bb_name}" -> "{c_name}";')
            except Exception:
                pass

        blocks.append(
            BasicBlockInfo(
                name=bb_name,
                start=start_off,
                end=end_off,
                instructions=ins_list,
                children=child_names,
            )
        )

        label_ins = "\\n".join(ins_list[:12]) if ins_list else "nop"
        if len(ins_list) > 12:
            label_ins += f"\\n... ({len(ins_list) - 12} more)"
        dot_lines.append(
            f'  "{bb_name}" [label="{bb_name}\\n[0x{start_off:x}-0x{end_off:x}]\\n\\n{label_ins}"];'
        )

    dot_lines.append("}")
    dot_graph = "\n".join(dot_lines)

    return ControlFlowGraph(
        method=method_name,
        blocks=blocks,
        dot=dot_graph,
    )
