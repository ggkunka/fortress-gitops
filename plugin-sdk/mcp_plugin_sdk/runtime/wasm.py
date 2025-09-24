"""
WebAssembly runtime support for secure plugin execution.
"""

import asyncio
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import logging

try:
    import wasmtime
    WASMTIME_AVAILABLE = True
except ImportError:
    WASMTIME_AVAILABLE = False

try:
    import wasmer
    WASMER_AVAILABLE = True
except ImportError:
    WASMER_AVAILABLE = False

from ..interfaces.base import BasePlugin, PluginContext, PluginMetadata, PluginStatus
from ..utils.exceptions import PluginError, SecurityError
from ..utils.logger import get_logger


class WasmResourceLimits:
    """Resource limits for WASM execution."""
    
    def __init__(
        self,
        max_memory_bytes: int = 64 * 1024 * 1024,  # 64MB
        max_execution_time_ms: int = 30000,  # 30 seconds
        max_fuel: Optional[int] = 1000000,  # Computation units
        max_stack_size: int = 1024 * 1024,  # 1MB
        enable_simd: bool = False,
        enable_bulk_memory: bool = False,
        enable_reference_types: bool = False
    ):
        self.max_memory_bytes = max_memory_bytes
        self.max_execution_time_ms = max_execution_time_ms
        self.max_fuel = max_fuel
        self.max_stack_size = max_stack_size
        self.enable_simd = enable_simd
        self.enable_bulk_memory = enable_bulk_memory
        self.enable_reference_types = enable_reference_types


class WasmSandbox:
    """
    WebAssembly sandbox for secure plugin execution.
    
    Provides isolated execution environment with resource limits,
    capability-based security, and host function injection.
    """
    
    def __init__(
        self,
        wasm_bytes: bytes,
        limits: WasmResourceLimits,
        allowed_host_functions: List[str] = None,
        runtime: str = "wasmtime"  # wasmtime, wasmer
    ):
        self.wasm_bytes = wasm_bytes
        self.limits = limits
        self.allowed_host_functions = allowed_host_functions or []
        self.runtime = runtime
        
        self.logger = get_logger("wasm_sandbox")
        
        # Runtime state
        self._engine = None
        self._store = None
        self._instance = None
        self._memory = None
        self._start_time = None
        self._fuel_consumed = 0
        
        # Host function registry
        self._host_functions = {}
        
    async def initialize(self) -> None:
        """Initialize the WASM runtime."""
        if self.runtime == "wasmtime" and WASMTIME_AVAILABLE:
            await self._initialize_wasmtime()
        elif self.runtime == "wasmer" and WASMER_AVAILABLE:
            await self._initialize_wasmer()
        else:
            raise PluginError(f"WASM runtime '{self.runtime}' not available")
    
    async def call_function(
        self,
        function_name: str,
        args: List[Any] = None,
        timeout_ms: Optional[int] = None
    ) -> Any:
        """
        Call a WASM function with arguments.
        
        Args:
            function_name: Name of the function to call
            args: Function arguments
            timeout_ms: Execution timeout in milliseconds
            
        Returns:
            Function return value
        """
        if not self._instance:
            raise PluginError("WASM sandbox not initialized")
        
        args = args or []
        timeout = timeout_ms or self.limits.max_execution_time_ms
        
        try:
            # Set start time for timeout tracking
            self._start_time = time.time()
            
            # Set fuel limit if supported
            if self.limits.max_fuel and hasattr(self._store, 'add_fuel'):
                self._store.add_fuel(self.limits.max_fuel)
            
            # Call function with timeout
            result = await asyncio.wait_for(
                self._call_function_impl(function_name, args),
                timeout=timeout / 1000.0
            )
            
            return result
            
        except asyncio.TimeoutError:
            self.logger.warning(f"WASM function {function_name} timed out")
            raise PluginError("Function execution timed out")
        except Exception as e:
            self.logger.error(f"WASM function {function_name} failed: {e}")
            raise PluginError(f"Function execution failed: {e}")
    
    async def read_memory(self, offset: int, length: int) -> bytes:
        """Read data from WASM memory."""
        if not self._memory:
            raise PluginError("WASM memory not available")
        
        try:
            if self.runtime == "wasmtime":
                return self._memory.read(self._store, offset, length)
            else:  # wasmer
                return bytes(self._memory.uint8_view(offset=offset)[0:length])
        except Exception as e:
            raise PluginError(f"Failed to read WASM memory: {e}")
    
    async def write_memory(self, offset: int, data: bytes) -> None:
        """Write data to WASM memory."""
        if not self._memory:
            raise PluginError("WASM memory not available")
        
        try:
            if self.runtime == "wasmtime":
                self._memory.write(self._store, data, offset)
            else:  # wasmer
                view = self._memory.uint8_view(offset=offset)
                view[0:len(data)] = data
        except Exception as e:
            raise PluginError(f"Failed to write WASM memory: {e}")
    
    def register_host_function(
        self,
        name: str,
        func: callable,
        params: List[str] = None,
        results: List[str] = None
    ) -> None:
        """
        Register a host function that can be called from WASM.
        
        Args:
            name: Function name
            func: Host function implementation
            params: Parameter types (i32, i64, f32, f64)
            results: Return types
        """
        if name not in self.allowed_host_functions:
            raise SecurityError(f"Host function '{name}' not allowed")
        
        self._host_functions[name] = {
            'func': func,
            'params': params or [],
            'results': results or []
        }
    
    async def get_memory_usage(self) -> int:
        """Get current memory usage in bytes."""
        if not self._memory:
            return 0
        
        try:
            if self.runtime == "wasmtime":
                return self._memory.size(self._store) * 65536  # Page size
            else:  # wasmer
                return len(self._memory.buffer)
        except Exception:
            return 0
    
    async def get_fuel_consumed(self) -> int:
        """Get fuel consumed (computation units used)."""
        if self.runtime == "wasmtime" and hasattr(self._store, 'fuel_consumed'):
            try:
                return self._store.fuel_consumed()
            except Exception:
                pass
        return self._fuel_consumed
    
    async def cleanup(self) -> None:
        """Cleanup the WASM sandbox."""
        self._instance = None
        self._memory = None
        self._store = None
        self._engine = None
    
    # Private methods
    
    async def _initialize_wasmtime(self) -> None:
        """Initialize Wasmtime runtime."""
        try:
            # Create engine with configuration
            config = wasmtime.Config()
            config.cache = True
            config.debug_info = False
            config.wasm_simd = self.limits.enable_simd
            config.wasm_bulk_memory = self.limits.enable_bulk_memory
            config.wasm_reference_types = self.limits.enable_reference_types
            config.consume_fuel = self.limits.max_fuel is not None
            
            self._engine = wasmtime.Engine(config)
            
            # Create store with resource limits
            self._store = wasmtime.Store(self._engine)
            
            # Set memory limits
            if hasattr(self._store, 'limiter'):
                limiter = wasmtime.StoreLimiter(
                    memory_size=self.limits.max_memory_bytes,
                    table_elements=1000,
                    instances=1,
                    tables=1,
                    memories=1
                )
                self._store.limiter(limiter)
            
            # Compile module
            module = wasmtime.Module(self._engine, self.wasm_bytes)
            
            # Create linker for host functions
            linker = wasmtime.Linker(self._engine)
            
            # Register host functions
            for name, func_info in self._host_functions.items():
                linker.define_func(
                    "env", name,
                    wasmtime.FuncType(
                        [self._wasmtime_type(t) for t in func_info['params']],
                        [self._wasmtime_type(t) for t in func_info['results']]
                    ),
                    func_info['func']
                )
            
            # Instantiate module
            self._instance = linker.instantiate(self._store, module)
            
            # Get memory export if available
            try:
                self._memory = self._instance.exports(self._store)["memory"]
            except KeyError:
                pass
            
            self.logger.info("Wasmtime sandbox initialized successfully")
            
        except Exception as e:
            raise PluginError(f"Failed to initialize Wasmtime: {e}")
    
    async def _initialize_wasmer(self) -> None:
        """Initialize Wasmer runtime."""
        try:
            # Create store
            self._store = wasmer.Store()
            
            # Compile module
            module = wasmer.Module(self._store, self.wasm_bytes)
            
            # Create imports for host functions
            imports = {}
            for name, func_info in self._host_functions.items():
                func_type = wasmer.FunctionType(
                    [self._wasmer_type(t) for t in func_info['params']],
                    [self._wasmer_type(t) for t in func_info['results']]
                )
                imports[name] = wasmer.Function(self._store, func_info['func'], func_type)
            
            # Instantiate module
            self._instance = wasmer.Instance(module, imports)
            
            # Get memory export if available
            try:
                self._memory = self._instance.exports.memory
            except AttributeError:
                pass
            
            self.logger.info("Wasmer sandbox initialized successfully")
            
        except Exception as e:
            raise PluginError(f"Failed to initialize Wasmer: {e}")
    
    async def _call_function_impl(self, function_name: str, args: List[Any]) -> Any:
        """Implementation-specific function call."""
        if self.runtime == "wasmtime":
            func = self._instance.exports(self._store)[function_name]
            return func(self._store, *args)
        else:  # wasmer
            func = getattr(self._instance.exports, function_name)
            return func(*args)
    
    def _wasmtime_type(self, type_str: str) -> wasmtime.ValType:
        """Convert type string to Wasmtime type."""
        type_map = {
            'i32': wasmtime.ValType.i32(),
            'i64': wasmtime.ValType.i64(),
            'f32': wasmtime.ValType.f32(),
            'f64': wasmtime.ValType.f64()
        }
        return type_map.get(type_str, wasmtime.ValType.i32())
    
    def _wasmer_type(self, type_str: str) -> wasmer.Type:
        """Convert type string to Wasmer type."""
        type_map = {
            'i32': wasmer.Type.I32,
            'i64': wasmer.Type.I64,
            'f32': wasmer.Type.F32,
            'f64': wasmer.Type.F64
        }
        return type_map.get(type_str, wasmer.Type.I32)


class WasmPlugin(BasePlugin):
    """
    WASM-based plugin implementation.
    
    Allows loading and executing plugins compiled to WebAssembly
    for maximum security and portability.
    """
    
    def __init__(
        self,
        context: PluginContext,
        wasm_file: Path,
        limits: Optional[WasmResourceLimits] = None,
        runtime: str = "wasmtime"
    ):
        super().__init__(context)
        self.wasm_file = wasm_file
        self.limits = limits or WasmResourceLimits()
        self.runtime = runtime
        
        self.sandbox: Optional[WasmSandbox] = None
        self._wasm_bytes = None
    
    async def initialize(self) -> None:
        """Initialize the WASM plugin."""
        try:
            self.logger.info(f"Loading WASM plugin from {self.wasm_file}")
            
            # Load WASM bytes
            with open(self.wasm_file, 'rb') as f:
                self._wasm_bytes = f.read()
            
            # Create sandbox
            self.sandbox = WasmSandbox(
                wasm_bytes=self._wasm_bytes,
                limits=self.limits,
                allowed_host_functions=self._get_allowed_host_functions(),
                runtime=self.runtime
            )
            
            # Register host functions
            await self._register_host_functions()
            
            # Initialize sandbox
            await self.sandbox.initialize()
            
            # Call plugin initialization function if available
            try:
                await self.sandbox.call_function("plugin_init")
            except PluginError:
                pass  # Init function not required
            
            self.logger.info("WASM plugin initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize WASM plugin: {e}")
            raise PluginError(f"WASM plugin initialization failed: {e}")
    
    async def shutdown(self) -> None:
        """Shutdown the WASM plugin."""
        try:
            # Call plugin shutdown function if available
            if self.sandbox:
                try:
                    await self.sandbox.call_function("plugin_shutdown")
                except PluginError:
                    pass  # Shutdown function not required
                
                await self.sandbox.cleanup()
                self.sandbox = None
            
            self.logger.info("WASM plugin shut down successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to shutdown WASM plugin: {e}")
    
    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata (should be overridden by subclasses)."""
        return PluginMetadata(
            name="wasm-plugin",
            version="1.0.0",
            description="WebAssembly plugin",
            plugin_type="processor",
            entry_point="wasm_plugin:WasmPlugin"
        )
    
    async def call_wasm_function(
        self,
        function_name: str,
        args: List[Any] = None,
        timeout_ms: Optional[int] = None
    ) -> Any:
        """
        Call a WASM function.
        
        Args:
            function_name: Name of the function to call
            args: Function arguments
            timeout_ms: Execution timeout
            
        Returns:
            Function result
        """
        if not self.sandbox:
            raise PluginError("WASM plugin not initialized")
        
        return await self.sandbox.call_function(function_name, args, timeout_ms)
    
    async def get_plugin_stats(self) -> Dict[str, Any]:
        """Get WASM plugin statistics."""
        stats = await super().get_metrics()
        
        if self.sandbox:
            stats.update({
                'memory_usage': await self.sandbox.get_memory_usage(),
                'fuel_consumed': await self.sandbox.get_fuel_consumed(),
                'wasm_runtime': self.runtime,
                'memory_limit': self.limits.max_memory_bytes,
                'execution_time_limit': self.limits.max_execution_time_ms
            })
        
        return stats
    
    def _get_allowed_host_functions(self) -> List[str]:
        """Get list of allowed host functions based on plugin capabilities."""
        allowed = []
        
        capabilities = getattr(self.get_metadata(), 'capabilities', None)
        if not capabilities:
            return allowed
        
        # Add functions based on required permissions
        if hasattr(capabilities, 'required_permissions'):
            permissions = capabilities.required_permissions
            
            if 'file_system_access' in permissions:
                allowed.extend(['fs_read', 'fs_write', 'fs_stat'])
            
            if 'network_access' in permissions:
                allowed.extend(['net_connect', 'net_send', 'net_receive'])
            
            if 'database_access' in permissions:
                allowed.extend(['db_query', 'db_execute'])
        
        # Always allow logging and basic functions
        allowed.extend(['log_debug', 'log_info', 'log_warn', 'log_error'])
        
        return allowed
    
    async def _register_host_functions(self) -> None:
        """Register host functions that WASM can call."""
        if not self.sandbox:
            return
        
        # Logging functions
        def log_info(level: int, message_ptr: int, message_len: int) -> None:
            try:
                message_bytes = asyncio.create_task(
                    self.sandbox.read_memory(message_ptr, message_len)
                )
                message = message_bytes.decode('utf-8')
                
                if level == 0:
                    self.logger.debug(f"WASM: {message}")
                elif level == 1:
                    self.logger.info(f"WASM: {message}")
                elif level == 2:
                    self.logger.warning(f"WASM: {message}")
                elif level == 3:
                    self.logger.error(f"WASM: {message}")
                    
            except Exception as e:
                self.logger.error(f"Failed to log from WASM: {e}")
        
        self.sandbox.register_host_function(
            'log_info',
            log_info,
            params=['i32', 'i32', 'i32'],
            results=[]
        )
        
        # File system functions (if permitted)
        if 'fs_read' in self.sandbox.allowed_host_functions:
            def fs_read(path_ptr: int, path_len: int, buf_ptr: int, buf_len: int) -> int:
                try:
                    path_bytes = asyncio.create_task(
                        self.sandbox.read_memory(path_ptr, path_len)
                    )
                    path = path_bytes.decode('utf-8')
                    
                    # Security: Only allow reading from plugin directory
                    if not path.startswith(self.context.working_directory):
                        return -1
                    
                    with open(path, 'rb') as f:
                        data = f.read(buf_len)
                    
                    asyncio.create_task(
                        self.sandbox.write_memory(buf_ptr, data)
                    )
                    
                    return len(data)
                    
                except Exception:
                    return -1
            
            self.sandbox.register_host_function(
                'fs_read',
                fs_read,
                params=['i32', 'i32', 'i32', 'i32'],
                results=['i32']
            )


class WasmPluginLoader:
    """
    Loader for WASM plugins.
    
    Handles compilation, validation, and instantiation of WASM plugins.
    """
    
    def __init__(self, runtime: str = "wasmtime"):
        self.runtime = runtime
        self.logger = get_logger("wasm_plugin_loader")
    
    async def load_plugin(
        self,
        wasm_file: Path,
        context: PluginContext,
        limits: Optional[WasmResourceLimits] = None
    ) -> WasmPlugin:
        """
        Load a WASM plugin from file.
        
        Args:
            wasm_file: Path to WASM file
            context: Plugin context
            limits: Resource limits
            
        Returns:
            Loaded WASM plugin
        """
        if not wasm_file.exists():
            raise PluginError(f"WASM file not found: {wasm_file}")
        
        # Validate WASM file
        await self._validate_wasm_file(wasm_file)
        
        # Create plugin instance
        plugin = WasmPlugin(context, wasm_file, limits, self.runtime)
        
        return plugin
    
    async def compile_plugin(
        self,
        source_files: List[Path],
        output_file: Path,
        compiler: str = "emscripten"
    ) -> bool:
        """
        Compile source files to WASM.
        
        Args:
            source_files: Source files to compile
            output_file: Output WASM file
            compiler: Compiler to use (emscripten, rust, etc.)
            
        Returns:
            True if compilation succeeded
        """
        try:
            if compiler == "emscripten":
                return await self._compile_with_emscripten(source_files, output_file)
            elif compiler == "rust":
                return await self._compile_with_rust(source_files, output_file)
            else:
                raise PluginError(f"Unsupported compiler: {compiler}")
                
        except Exception as e:
            self.logger.error(f"Compilation failed: {e}")
            return False
    
    async def _validate_wasm_file(self, wasm_file: Path) -> None:
        """Validate WASM file format and security."""
        with open(wasm_file, 'rb') as f:
            header = f.read(8)
        
        # Check WASM magic number
        if header[:4] != b'\x00asm':
            raise PluginError("Invalid WASM file: missing magic number")
        
        # Check version
        version = int.from_bytes(header[4:8], 'little')
        if version != 1:
            raise PluginError(f"Unsupported WASM version: {version}")
        
        self.logger.debug(f"WASM file validation passed: {wasm_file}")
    
    async def _compile_with_emscripten(self, source_files: List[Path], output_file: Path) -> bool:
        """Compile with Emscripten."""
        # This would implement Emscripten compilation
        # For now, just a placeholder
        self.logger.info("Emscripten compilation not implemented")
        return False
    
    async def _compile_with_rust(self, source_files: List[Path], output_file: Path) -> bool:
        """Compile with Rust."""
        # This would implement Rust WASM compilation
        # For now, just a placeholder
        self.logger.info("Rust WASM compilation not implemented")
        return False