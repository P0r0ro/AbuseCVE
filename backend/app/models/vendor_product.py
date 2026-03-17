"""Normalized Vendor & Product models — the CPE "Golden List" entity system.

Vendors and Products are pre-populated from the NVD Official CPE Dictionary,
then linked to CVE records via foreign keys for data integrity.

Aliases support mapping inconsistent names (e.g. "Cisco Systems" → "cisco")
back to the canonical vendor/product.
"""

from __future__ import annotations

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime,
    ForeignKey, Index, UniqueConstraint,
)
from sqlalchemy.orm import relationship
from app.database import Base


class Vendor(Base):
    """Canonical vendor entity from the CPE dictionary.

    The `name` field stores the CPE-normalized lowercase name (e.g. "cisco").
    `display_name` stores a human-readable version (e.g. "Cisco Systems").
    """
    __tablename__ = "vendors"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), unique=True, nullable=False, index=True)
    display_name = Column(String(255), nullable=True)
    is_cpe_source = Column(Boolean, default=False)  # True if from official CPE dict
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    products = relationship("Product", back_populates="vendor", lazy="selectin")
    aliases = relationship("VendorAlias", back_populates="vendor", lazy="selectin")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "display_name": self.display_name,
            "is_cpe_source": self.is_cpe_source,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Product(Base):
    """Canonical product entity linked to a vendor.

    The `name` field stores the CPE-normalized lowercase name (e.g. "ios_xe").
    `display_name` stores a human-readable version (e.g. "IOS XE").
    """
    __tablename__ = "products"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, index=True)
    display_name = Column(String(255), nullable=True)
    vendor_id = Column(Integer, ForeignKey("vendors.id", ondelete="CASCADE"), nullable=False, index=True)
    is_cpe_source = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    vendor = relationship("Vendor", back_populates="products")
    aliases = relationship("ProductAlias", back_populates="product", lazy="selectin")

    __table_args__ = (
        UniqueConstraint("vendor_id", "name", name="uq_product_vendor_name"),
        Index("ix_products_vendor_name", "vendor_id", "name"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "display_name": self.display_name,
            "vendor_id": self.vendor_id,
            "vendor_name": self.vendor.name if self.vendor else None,
            "is_cpe_source": self.is_cpe_source,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class VendorAlias(Base):
    """Alternative names that map to a canonical vendor.

    Examples: "Cisco Systems" → vendor(name="cisco")
              "Cisco Systems, Inc." → vendor(name="cisco")
    """
    __tablename__ = "vendor_aliases"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alias = Column(String(255), unique=True, nullable=False, index=True)
    vendor_id = Column(Integer, ForeignKey("vendors.id", ondelete="CASCADE"), nullable=False)

    vendor = relationship("Vendor", back_populates="aliases")


class ProductAlias(Base):
    """Alternative names that map to a canonical product.

    Examples: "Internet Explorer" → product(name="ie")
              "IE" → product(name="ie")
    """
    __tablename__ = "product_aliases"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alias = Column(String(255), nullable=False, index=True)
    product_id = Column(Integer, ForeignKey("products.id", ondelete="CASCADE"), nullable=False)

    product = relationship("Product", back_populates="aliases")

    __table_args__ = (
        UniqueConstraint("alias", "product_id", name="uq_product_alias"),
    )


class CPESyncStatus(Base):
    """Tracks the last successful CPE dictionary sync."""
    __tablename__ = "cpe_sync_status"

    id = Column(Integer, primary_key=True, autoincrement=True)
    last_sync_at = Column(DateTime, nullable=True)
    total_vendors = Column(Integer, default=0)
    total_products = Column(Integer, default=0)
    status = Column(String(20), default="pending")  # pending, running, completed, failed
    error_message = Column(Text, nullable=True)
    duration_seconds = Column(Integer, nullable=True)
