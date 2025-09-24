"""Validation service for ingestion data."""

from typing import Any, Dict, List, Optional, Tuple, Union
from datetime import datetime

import structlog
from pydantic import ValidationError

from ..schemas import SBOMSchema, CVESchema, RuntimeBehaviorSchema

logger = structlog.get_logger()


class ValidationResult:
    """Validation result container."""
    
    def __init__(self, is_valid: bool, data: Optional[Dict[str, Any]] = None, errors: Optional[List[str]] = None):
        self.is_valid = is_valid
        self.data = data or {}
        self.errors = errors or []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "is_valid": self.is_valid,
            "data": self.data,
            "errors": self.errors,
        }


class ValidationService:
    """Service for validating ingestion data."""
    
    def __init__(self):
        """Initialize validation service."""
        self.schema_mapping = {
            "sbom": SBOMSchema,
            "cve": CVESchema,
            "runtime": RuntimeBehaviorSchema,
        }
    
    async def validate_sbom(self, data: Dict[str, Any]) -> ValidationResult:
        """Validate SBOM data."""
        return await self._validate_data(data, "sbom")
    
    async def validate_cve(self, data: Dict[str, Any]) -> ValidationResult:
        """Validate CVE data."""
        return await self._validate_data(data, "cve")
    
    async def validate_runtime(self, data: Dict[str, Any]) -> ValidationResult:
        """Validate runtime behavior data."""
        return await self._validate_data(data, "runtime")
    
    async def _validate_data(self, data: Dict[str, Any], data_type: str) -> ValidationResult:
        """Validate data against schema."""
        try:
            schema_class = self.schema_mapping.get(data_type)
            if not schema_class:
                return ValidationResult(
                    is_valid=False,
                    errors=[f"Unknown data type: {data_type}"]
                )
            
            # Validate with Pydantic
            validated_data = schema_class(**data)
            
            # Convert to dict for serialization
            validated_dict = validated_data.model_dump()
            
            logger.info(
                "Data validation successful",
                data_type=data_type,
                ingestion_id=validated_dict.get("ingestion_id"),
            )
            
            return ValidationResult(
                is_valid=True,
                data=validated_dict,
            )
        
        except ValidationError as e:
            errors = []
            for error in e.errors():
                field_path = " -> ".join(str(loc) for loc in error["loc"])
                error_msg = f"{field_path}: {error['msg']}"
                errors.append(error_msg)
            
            logger.warning(
                "Data validation failed",
                data_type=data_type,
                error_count=len(errors),
                errors=errors[:5],  # Log first 5 errors
            )
            
            return ValidationResult(
                is_valid=False,
                errors=errors,
            )
        
        except Exception as e:
            logger.error(
                "Unexpected validation error",
                data_type=data_type,
                error=str(e),
            )
            
            return ValidationResult(
                is_valid=False,
                errors=[f"Unexpected validation error: {str(e)}"],
            )
    
    async def validate_data_type(self, data: Dict[str, Any], expected_type: str) -> ValidationResult:
        """Validate data against expected type."""
        if expected_type == "sbom":
            return await self.validate_sbom(data)
        elif expected_type == "cve":
            return await self.validate_cve(data)
        elif expected_type == "runtime":
            return await self.validate_runtime(data)
        else:
            return ValidationResult(
                is_valid=False,
                errors=[f"Unknown data type: {expected_type}"]
            )
    
    def get_schema_info(self, data_type: str) -> Optional[Dict[str, Any]]:
        """Get schema information for a data type."""
        schema_class = self.schema_mapping.get(data_type)
        if not schema_class:
            return None
        
        return {
            "data_type": data_type,
            "schema_name": schema_class.__name__,
            "schema_version": "1.0.0",
            "fields": list(schema_class.model_fields.keys()),
            "required_fields": [
                field_name for field_name, field_info in schema_class.model_fields.items()
                if field_info.is_required()
            ],
            "example": schema_class.model_config.get("schema_extra", {}).get("example"),
        }
    
    def get_all_schema_info(self) -> Dict[str, Any]:
        """Get information about all supported schemas."""
        return {
            data_type: self.get_schema_info(data_type)
            for data_type in self.schema_mapping.keys()
        }
    
    async def pre_validate_json(self, json_data: str) -> Tuple[bool, Optional[Dict[str, Any]], List[str]]:
        """Pre-validate JSON data before schema validation."""
        try:
            import json
            data = json.loads(json_data)
            
            # Basic structure validation
            if not isinstance(data, dict):
                return False, None, ["Data must be a JSON object"]
            
            # Check for completely empty data
            if not data:
                return False, None, ["Data cannot be empty"]
            
            return True, data, []
        
        except json.JSONDecodeError as e:
            return False, None, [f"Invalid JSON: {str(e)}"]
        except Exception as e:
            return False, None, [f"Unexpected error parsing JSON: {str(e)}"]
    
    async def validate_batch(
        self,
        batch_data: List[Dict[str, Any]],
        data_type: str,
        stop_on_first_error: bool = False,
    ) -> Dict[str, Any]:
        """Validate a batch of data items."""
        results = {
            "total": len(batch_data),
            "valid": 0,
            "invalid": 0,
            "results": [],
            "errors": [],
        }
        
        for i, item in enumerate(batch_data):
            try:
                result = await self.validate_data_type(item, data_type)
                
                result_item = {
                    "index": i,
                    "is_valid": result.is_valid,
                    "errors": result.errors,
                }
                
                if result.is_valid:
                    results["valid"] += 1
                    result_item["data"] = result.data
                else:
                    results["invalid"] += 1
                    results["errors"].extend([f"Item {i}: {error}" for error in result.errors])
                
                results["results"].append(result_item)
                
                # Stop on first error if requested
                if stop_on_first_error and not result.is_valid:
                    break
            
            except Exception as e:
                results["invalid"] += 1
                error_msg = f"Item {i}: Unexpected error: {str(e)}"
                results["errors"].append(error_msg)
                
                results["results"].append({
                    "index": i,
                    "is_valid": False,
                    "errors": [error_msg],
                })
                
                if stop_on_first_error:
                    break
        
        return results
    
    async def validate_field_constraints(
        self,
        data: Dict[str, Any],
        data_type: str,
        custom_constraints: Optional[Dict[str, Any]] = None,
    ) -> ValidationResult:
        """Validate data against custom field constraints."""
        errors = []
        
        # Apply custom constraints if provided
        if custom_constraints:
            for field_name, constraint in custom_constraints.items():
                field_value = data.get(field_name)
                
                if field_value is None:
                    continue
                
                # Check min/max constraints
                if "min_length" in constraint and isinstance(field_value, str):
                    if len(field_value) < constraint["min_length"]:
                        errors.append(
                            f"{field_name}: minimum length {constraint['min_length']} required"
                        )
                
                if "max_length" in constraint and isinstance(field_value, str):
                    if len(field_value) > constraint["max_length"]:
                        errors.append(
                            f"{field_name}: maximum length {constraint['max_length']} exceeded"
                        )
                
                if "min_value" in constraint and isinstance(field_value, (int, float)):
                    if field_value < constraint["min_value"]:
                        errors.append(
                            f"{field_name}: minimum value {constraint['min_value']} required"
                        )
                
                if "max_value" in constraint and isinstance(field_value, (int, float)):
                    if field_value > constraint["max_value"]:
                        errors.append(
                            f"{field_name}: maximum value {constraint['max_value']} exceeded"
                        )
                
                # Check allowed values
                if "allowed_values" in constraint:
                    if field_value not in constraint["allowed_values"]:
                        errors.append(
                            f"{field_name}: value must be one of {constraint['allowed_values']}"
                        )
                
                # Check regex pattern
                if "pattern" in constraint and isinstance(field_value, str):
                    import re
                    if not re.match(constraint["pattern"], field_value):
                        errors.append(
                            f"{field_name}: value does not match required pattern"
                        )
        
        if errors:
            return ValidationResult(is_valid=False, errors=errors)
        
        # If custom constraints pass, validate with schema
        return await self.validate_data_type(data, data_type)
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on validation service."""
        return {
            "service": "validation",
            "status": "healthy",
            "supported_schemas": list(self.schema_mapping.keys()),
            "timestamp": datetime.utcnow().isoformat(),
        }