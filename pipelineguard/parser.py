"""YAML parser preserving source line numbers and Abstract Syntax Tree (AST) metadata."""

from pathlib import Path
from typing import Any, Optional, Tuple, Union
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq


class WorkflowParser:
    """Parses GitHub Actions YAML files using ruamel.yaml round-trip mode to preserve AST line positions."""

    def __init__(self) -> None:
        self.yaml = YAML(typ="rt")
        self.yaml.preserve_quotes = True

    def parse_string(self, content: str) -> Any:
        """Parse raw YAML string into ruamel.yaml AST structure."""
        return self.yaml.load(content)

    def parse_file(self, file_path: Union[str, Path]) -> Tuple[Any, str]:
        """Parse a workflow YAML file, returning the AST and raw content string."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Workflow file not found: {path}")

        raw_content = path.read_text(encoding="utf-8")
        parsed_ast = self.yaml.load(raw_content)
        return parsed_ast, raw_content

    @staticmethod
    def get_line(node: Any, key: Optional[str] = None, default: int = 1) -> int:
        """Extract 1-indexed line number from ruamel.yaml AST node or map key.
        
        ruamel.yaml stores line positions in 0-indexed format under the `.lc` attribute.
        """
        if node is None:
            return default

        try:
            if key is not None and hasattr(node, "lc"):
                # Try getting the exact key position
                key_pos = node.lc.key(key)
                if key_pos is not None:
                    return int(key_pos[0]) + 1

                # If key not found, try getting value position
                val_pos = node.lc.value(key)
                if val_pos is not None:
                    return int(val_pos[0]) + 1

            # Fallback to the node's own line position
            if hasattr(node, "lc") and hasattr(node.lc, "line"):
                if node.lc.line is not None:
                    return int(node.lc.line) + 1
        except Exception:
            pass

        return default
