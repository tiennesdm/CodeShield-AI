"""
Data models for the TestParser agent.

Defines Pydantic models for parsed code structures including functions,
classes, modules, and arguments extracted from AST analysis.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ParsedArg(BaseModel):
    """Represents a single function/method argument."""

    name: str
    type_annotation: Optional[str] = None
    default_value: Optional[str] = None
    is_vararg: bool = False
    is_kwarg: bool = False
    is_kwonly: bool = False
    is_posonly: bool = False


class ParsedFunction(BaseModel):
    """
    Represents a parsed function, method, or async function.

    Captures all metadata needed for automatic test generation including
    signature, decorators, docstring, complexity, and exception types.
    """

    name: str
    qualified_name: str  # module.Class.method or module.function
    file_path: str
    line_start: int
    line_end: int
    args: List[ParsedArg] = Field(default_factory=list)
    return_type: Optional[str] = None
    decorators: List[str] = Field(default_factory=list)
    docstring: Optional[str] = None
    is_async: bool = False
    is_method: bool = False
    is_classmethod: bool = False
    is_staticmethod: bool = False
    is_private: bool = False  # _name or __name
    is_property_getter: bool = False
    is_property_setter: bool = False
    is_constructor: bool = False  # __init__, constructor, etc.
    raises: List[str] = Field(default_factory=list)  # Exception types
    complexity: int = 1  # Cyclomatic complexity
    body_snippet: Optional[str] = None  # First N lines of body for context

    def to_test_target_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary suitable for test generation prompts."""
        return {
            "qualified_name": self.qualified_name,
            "signature": self._format_signature(),
            "return_type": self.return_type,
            "args": [
                {
                    "name": a.name,
                    "type": a.type_annotation,
                    "default": a.default_value,
                }
                for a in self.args
            ],
            "is_async": self.is_async,
            "is_method": self.is_method,
            "is_static": self.is_staticmethod,
            "is_classmethod": self.is_classmethod,
            "is_private": self.is_private,
            "is_property": self.is_property_getter or self.is_property_setter,
            "is_constructor": self.is_constructor,
            "raises": self.raises,
            "complexity": self.complexity,
            "docstring": self.docstring,
        }

    def _format_signature(self) -> str:
        """Reconstruct a human-readable signature string."""
        decorator_str = ""
        for dec in self.decorators:
            decorator_str += f"@{dec}\n"

        async_prefix = "async " if self.is_async else ""

        # Build args string
        arg_parts = []
        for arg in self.args:
            part = arg.name
            if arg.type_annotation:
                part += f": {arg.type_annotation}"
            if arg.default_value:
                part += f" = {arg.default_value}"
            if arg.is_vararg:
                part = f"*{part}"
            if arg.is_kwarg:
                part = f"**{part}"
            arg_parts.append(part)

        args_str = ", ".join(arg_parts)
        return_part = f" -> {self.return_type}" if self.return_type else ""

        sig = f"{async_prefix}def {self.name}({args_str}){return_part}"
        if decorator_str:
            sig = decorator_str + sig
        return sig


class ParsedClass(BaseModel):
    """
    Represents a parsed class with its methods.

    Captures class-level information including inheritance hierarchy,
    method list, and docstring.
    """

    name: str
    qualified_name: str  # module.Class
    file_path: str
    line_start: int
    line_end: int
    methods: List[ParsedFunction] = Field(default_factory=list)
    bases: List[str] = Field(default_factory=list)  # Inheritance
    docstring: Optional[str] = None
    decorators: List[str] = Field(default_factory=list)
    is_dataclass: bool = False
    module_path: Optional[str] = None  # dotted module path

    def get_testable_methods(self) -> List[ParsedFunction]:
        """Return methods that should have tests (exclude private unless configured)."""
        return [
            m for m in self.methods
            if not m.is_private or m.is_constructor
        ]

    def get_public_methods(self) -> List[ParsedFunction]:
        """Return only public methods."""
        return [m for m in self.methods if not m.is_private]

    def get_constructors(self) -> List[ParsedFunction]:
        """Return constructor/init methods."""
        return [m for m in self.methods if m.is_constructor]

    def total_complexity(self) -> int:
        """Sum complexity of all methods."""
        return sum(m.complexity for m in self.methods)

    def to_test_target_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary suitable for test generation prompts."""
        return {
            "qualified_name": self.qualified_name,
            "name": self.name,
            "bases": self.bases,
            "method_count": len(self.methods),
            "public_methods": [
                m.to_test_target_dict() for m in self.get_public_methods()
            ],
            "constructors": [
                m.to_test_target_dict() for m in self.get_constructors()
            ],
            "total_complexity": self.total_complexity(),
            "docstring": self.docstring,
        }


class ParsedModule(BaseModel):
    """
    Represents a parsed source file (module).

    Top-level container that holds all functions, classes, and imports
    extracted from a single source file.
    """

    file_path: str
    language: str
    functions: List[ParsedFunction] = Field(default_factory=list)
    classes: List[ParsedClass] = Field(default_factory=list)
    imports: List[str] = Field(default_factory=list)
    total_lines: int = 0
    module_docstring: Optional[str] = None

    def all_functions(self) -> List[ParsedFunction]:
        """Return all functions including class methods."""
        all_funcs = list(self.functions)
        for cls in self.classes:
            all_funcs.extend(cls.methods)
        return all_funcs

    def get_testable_units(self) -> List[ParsedFunction]:
        """Return all testable functions (non-private, non-abstract where possible)."""
        units = []
        for func in self.all_functions():
            # Skip private functions by default
            if not func.is_private:
                units.append(func)
        return units

    def get_by_qualified_name(self, qname: str) -> Optional[ParsedFunction]:
        """Look up a function by its qualified name."""
        for func in self.all_functions():
            if func.qualified_name == qname:
                return func
        return None

    def summary(self) -> Dict[str, Any]:
        """Return a summary of the parsed module."""
        all_funcs = self.all_functions()
        return {
            "file_path": self.file_path,
            "language": self.language,
            "total_lines": self.total_lines,
            "top_level_functions": len(self.functions),
            "classes": len(self.classes),
            "total_methods": sum(len(c.methods) for c in self.classes),
            "total_functions": len(all_funcs),
            "async_functions": sum(1 for f in all_funcs if f.is_async),
            "total_complexity": sum(f.complexity for f in all_funcs),
            "imports": len(self.imports),
        }


class ParserResult(BaseModel):
    """
    Aggregate result from parsing multiple files.

    Returned by the TestParserAgent after scanning a codebase.
    """

    modules: List[ParsedModule] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    files_parsed: int = 0
    files_failed: int = 0

    def all_functions(self) -> List[ParsedFunction]:
        """Return all functions across all modules."""
        result = []
        for mod in self.modules:
            result.extend(mod.all_functions())
        return result

    def all_classes(self) -> List[ParsedClass]:
        """Return all classes across all modules."""
        result = []
        for mod in self.modules:
            result.extend(mod.classes)
        return result

    def get_by_qualified_name(self, qname: str) -> Optional[ParsedFunction]:
        """Look up a function across all modules."""
        for mod in self.modules:
            func = mod.get_by_qualified_name(qname)
            if func:
                return func
        return None

    def summary(self) -> Dict[str, Any]:
        """Return a summary of all parsed modules."""
        all_funcs = self.all_functions()
        all_classes = self.all_classes()
        return {
            "files_parsed": self.files_parsed,
            "files_failed": self.files_failed,
            "total_modules": len(self.modules),
            "total_functions": len(all_funcs),
            "total_classes": len(all_classes),
            "total_methods": sum(len(c.methods) for c in all_classes),
            "async_functions": sum(1 for f in all_funcs if f.is_async),
            "total_complexity": sum(f.complexity for f in all_funcs),
            "avg_complexity": (
                sum(f.complexity for f in all_funcs) / len(all_funcs)
                if all_funcs else 0
            ),
            "errors": self.errors,
        }
