"""
ThreatIQ v4.0 -- ORM models.
"""
import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean, DateTime, Enum, Float, ForeignKey, Index, Integer,
    JSON, String, Text, UniqueConstraint, func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def gen_uuid() -> str:
    return str(uuid.uuid4())


class TLPLevel(str, enum.Enum):
    WHITE = "TLP:WHITE"
    GREEN = "TLP:GREEN"
    AMBER = "TLP:AMBER"
    RED = "TLP:RED"


class IoCSourceType(str, enum.Enum):
    MISP = "MISP"
    CIRCL = "CIRCL"
    SIEM = "Internal SIEM"
    VIRUSTOTAL = "VirusTotal"
    SHODAN = "Shodan"
    OTX = "OTX AlienVault"
    IBM_XFORCE = "IBM X-Force"
    RECORDED_FUTURE = "Recorded Future"
    STIX_TAXII = "STIX/TAXII"
    SYNTHETIC = "Synthetic"


class IngestionStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


class FeedbackAction(str, enum.Enum):
    WEIGHT_UP = "weight_up"
    WEIGHT_DOWN = "weight_down"
    NO_CHANGE = "no_change"


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    max_tlp_level: Mapped[str] = mapped_column(String(16), default="TLP:AMBER")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    iocs: Mapped[list["IoC"]] = relationship(back_populates="tenant", cascade="all, delete-orphan")


class IngestionRun(Base):
    __tablename__ = "ingestion_runs"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    records_fetched: Mapped[int] = mapped_column(Integer, default=0)
    records_ingested: Mapped[int] = mapped_column(Integer, default=0)
    records_rejected: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    cursor_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    config_snapshot: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class IoC(Base):
    __tablename__ = "iocs"
    __table_args__ = (
        Index("ix_iocs_tenant_label", "tenant_id", "label"),
        Index("ix_iocs_tenant_severity", "tenant_id", "severity"),
        Index("ix_iocs_source", "source"),
        Index("ix_iocs_is_anomaly", "is_anomaly"),
        UniqueConstraint("tenant_id", "external_id", "source", name="uq_ioc_external_per_tenant_source"),
    )
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    ingestion_run_id: Mapped[str | None] = mapped_column(ForeignKey("ingestion_runs.id"), nullable=True)
    external_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    label: Mapped[str] = mapped_column(String(64), nullable=False)
    label_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[int] = mapped_column(Integer, nullable=False)
    severity_label: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    source_trust: Mapped[float] = mapped_column(Float, default=0.5)
    composite_score: Mapped[float] = mapped_column(Float, default=0.0)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False)
    threat_actor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ttp: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ttp_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ioc_value: Mapped[str] = mapped_column(Text, nullable=False)
    ioc_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="New")
    tlp: Mapped[str] = mapped_column(String(16), default="TLP:AMBER")
    country: Mapped[str | None] = mapped_column(String(8), nullable=True)
    sector: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    raw_payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    tenant: Mapped["Tenant"] = relationship(back_populates="iocs")
    feedback: Mapped[list["AnalystFeedback"]] = relationship(back_populates="ioc", cascade="all, delete-orphan")


class GraphNode(Base):
    __tablename__ = "graph_nodes"
    __table_args__ = (UniqueConstraint("tenant_id", "node_key", name="uq_graph_node_per_tenant"),)
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    node_key: Mapped[str] = mapped_column(String(255), nullable=False)
    node_type: Mapped[str] = mapped_column(String(32), nullable=False)
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    weight: Mapped[float] = mapped_column(Float, default=0.7)
    is_dynamic: Mapped[bool] = mapped_column(Boolean, default=False)
    extra: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    embedding: Mapped[list | None] = mapped_column(JSON, nullable=True)
    embedding_version: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class GraphEdge(Base):
    __tablename__ = "graph_edges"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    source_node_id: Mapped[str] = mapped_column(ForeignKey("graph_nodes.id"), nullable=False)
    target_node_id: Mapped[str] = mapped_column(ForeignKey("graph_nodes.id"), nullable=False)
    relation: Mapped[str] = mapped_column(String(64), nullable=False)
    attention_weight: Mapped[float] = mapped_column(Float, default=0.5)
    is_dynamic: Mapped[bool] = mapped_column(Boolean, default=False)
    is_predicted: Mapped[bool] = mapped_column(Boolean, default=False)
    confirmed_ground_truth: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class GraphVersion(Base):
    __tablename__ = "graph_versions"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    node_count: Mapped[int] = mapped_column(Integer, default=0)
    edge_count: Mapped[int] = mapped_column(Integer, default=0)
    trigger: Mapped[str] = mapped_column(String(64), default="manual")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class MitreRelationship(Base):
    __tablename__ = "mitre_relationships"
    __table_args__ = (UniqueConstraint("group_id", "technique_id", name="uq_mitre_group_technique"),)
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    group_id: Mapped[str] = mapped_column(String(32), nullable=False)
    group_name: Mapped[str] = mapped_column(String(255), nullable=False)
    technique_id: Mapped[str] = mapped_column(String(32), nullable=False)
    technique_name: Mapped[str] = mapped_column(String(255), nullable=False)
    source: Mapped[str] = mapped_column(String(32), default="mitre-attack")
    split: Mapped[str] = mapped_column(String(16), default="train")


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"
    __table_args__ = (Index("ix_feedback_ioc", "ioc_id"),)
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    ioc_id: Mapped[str] = mapped_column(ForeignKey("iocs.id"), nullable=False)
    analyst_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    predicted_class: Mapped[str] = mapped_column(String(64), nullable=False)
    true_class: Mapped[str] = mapped_column(String(64), nullable=False)
    is_correct: Mapped[bool] = mapped_column(Boolean, nullable=False)
    analyst_confidence: Mapped[float] = mapped_column(Float, default=0.8)
    action_taken: Mapped[str] = mapped_column(String(16), nullable=False)
    reward: Mapped[float] = mapped_column(Float, nullable=False)
    q_value_delta: Mapped[float] = mapped_column(Float, default=0.0)
    weights_snapshot: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    ioc: Mapped["IoC"] = relationship(back_populates="feedback")


class RLPolicyState(Base):
    __tablename__ = "rl_policy_state"
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), primary_key=True)
    q_table: Mapped[dict] = mapped_column(JSON, default=dict)
    class_weights: Mapped[dict] = mapped_column(JSON, default=dict)
    alpha: Mapped[float] = mapped_column(Float, default=0.15)
    gamma: Mapped[float] = mapped_column(Float, default=0.90)
    epsilon: Mapped[float] = mapped_column(Float, default=0.10)
    total_updates: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ModelEvaluationRun(Base):
    __tablename__ = "model_evaluation_runs"
    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    model_name: Mapped[str] = mapped_column(String(64), nullable=False)
    dataset_type: Mapped[str] = mapped_column(String(32), nullable=False)
    dataset_size: Mapped[int] = mapped_column(Integer, nullable=False)
    metrics: Mapped[dict] = mapped_column(JSON, nullable=False)
    model_version: Mapped[str] = mapped_column(String(64), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
