"""
Base Database Models

Common base classes and utilities for all database models.
"""

import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import Column, DateTime, String, Text, JSON, Boolean, event
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session

Base = declarative_base()


class TimestampMixin:
    """Mixin for created_at and updated_at timestamps."""
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class UUIDMixin:
    """Mixin for UUID primary keys."""
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


class SoftDeleteMixin:
    """Mixin for soft delete functionality."""
    
    deleted_at = Column(DateTime, nullable=True)
    is_deleted = Column(Boolean, default=False, nullable=False)
    
    def soft_delete(self):
        """Mark record as deleted."""
        self.is_deleted = True
        self.deleted_at = datetime.utcnow()
    
    def restore(self):
        """Restore soft-deleted record."""
        self.is_deleted = False
        self.deleted_at = None


class MetadataMixin:
    """Mixin for storing additional metadata."""
    
    metadata = Column(JSON, default=dict, nullable=False)
    
    def set_metadata(self, key: str, value: Any):
        """Set metadata value."""
        if self.metadata is None:
            self.metadata = {}
        self.metadata[key] = value
    
    def get_metadata(self, key: str, default: Any = None) -> Any:
        """Get metadata value."""
        if self.metadata is None:
            return default
        return self.metadata.get(key, default)


class AuditMixin:
    """Mixin for audit trail information."""
    
    created_by = Column(UUID(as_uuid=True), nullable=True)
    updated_by = Column(UUID(as_uuid=True), nullable=True)
    version = Column(String(50), default="1.0", nullable=False)
    
    def set_audit_info(self, user_id: Optional[uuid.UUID], action: str = "update"):
        """Set audit information."""
        if action == "create":
            self.created_by = user_id
        else:
            self.updated_by = user_id


class BaseModel(Base, UUIDMixin, TimestampMixin, SoftDeleteMixin, MetadataMixin, AuditMixin):
    """Base model class with all common functionality."""
    
    __abstract__ = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary."""
        result = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            if isinstance(value, datetime):
                value = value.isoformat()
            elif isinstance(value, uuid.UUID):
                value = str(value)
            result[column.name] = value
        return result
    
    def update_from_dict(self, data: Dict[str, Any], exclude: Optional[list] = None):
        """Update model from dictionary."""
        if exclude is None:
            exclude = ['id', 'created_at', 'updated_at']
        
        for key, value in data.items():
            if key not in exclude and hasattr(self, key):
                setattr(self, key, value)
    
    @classmethod
    def create(cls, session: Session, **kwargs) -> "BaseModel":
        """Create and save new instance."""
        instance = cls(**kwargs)
        session.add(instance)
        session.flush()
        return instance
    
    def save(self, session: Session) -> "BaseModel":
        """Save instance to database."""
        session.add(self)
        session.flush()
        return self
    
    def delete(self, session: Session, soft: bool = True):
        """Delete instance (soft delete by default)."""
        if soft:
            self.soft_delete()
            session.flush()
        else:
            session.delete(self)
            session.flush()


# Event listeners for automatic timestamping
@event.listens_for(BaseModel, 'before_insert', propagate=True)
def receive_before_insert(mapper, connection, target):
    """Set created_at and updated_at before insert."""
    target.created_at = datetime.utcnow()
    target.updated_at = datetime.utcnow()


@event.listens_for(BaseModel, 'before_update', propagate=True)
def receive_before_update(mapper, connection, target):
    """Set updated_at before update."""
    target.updated_at = datetime.utcnow()


class ValidationMixin:
    """Mixin for model validation."""
    
    def validate(self) -> list:
        """Validate model data. Return list of errors."""
        errors = []
        
        # Custom validation logic can be implemented in subclasses
        if hasattr(self, '_validate'):
            errors.extend(self._validate())
        
        return errors
    
    def is_valid(self) -> bool:
        """Check if model is valid."""
        return len(self.validate()) == 0