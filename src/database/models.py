import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    Boolean,
    Float,
    DateTime,
    Index,
    CheckConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import declarative_base

Base = declarative_base()

def _utcnow():
    return datetime.now(timezone.utc)

class ThreatLog(Base):
    __tablename__ = "threat_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    request_id = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    client_ip = Column(String, nullable=False)
    application_id = Column(String, nullable=False)
    target_model = Column(String, nullable=False)
    raw_prompt = Column(Text, nullable=False)
    system_instruction = Column(Text, nullable=True)
    is_blocked = Column(Boolean, default=False, nullable=False)
    action_taken = Column(String, nullable=False) 
    triggered_layer = Column(String, nullable=False) 
    risk_score = Column(Float, nullable=False)
    execution_time_ms = Column(Float, nullable=False)
    layer_details = Column(JSONB, nullable=True)
    detected_patterns = Column(JSONB, nullable=True)
    output_completion = Column(Text, nullable=True)
    output_flagged = Column(Boolean, default=False, nullable=False)

    __table_args__ = (
        Index("ix_threat_logs_request_id", "request_id", unique=True),
        Index("ix_threat_logs_created_at_desc", created_at.desc()),
        Index("ix_threat_logs_is_blocked", "is_blocked"),
        Index("ix_threat_logs_triggered_layer", "triggered_layer"),
        Index("ix_threat_logs_client_ip", "client_ip"),
        Index("ix_threat_logs_risk_score", "risk_score"),
        Index("ix_threat_logs_created_at_is_blocked", "created_at", "is_blocked"),
        Index("ix_threat_logs_layer_details_gin", "layer_details", postgresql_using="gin"),
        CheckConstraint(
            "action_taken IN ('PASSED', 'BLOCKED', 'REDACTED')",
            name="check_action_taken"
        ),
        CheckConstraint(
            "triggered_layer IN ('NONE', 'LAYER_1', 'LAYER_2', 'LAYER_3', 'OUTPUT_SCANNER')",
            name="check_triggered_layer"
        ),
    )


class FirewallRule(Base):
    __tablename__ = "firewall_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_id = Column(String, unique=True, nullable=False)
    rule_type = Column(String, nullable=False)     
    category = Column(String, nullable=False)
    pattern = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, nullable=False) 
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (
        Index("ix_firewall_rules_rule_id", "rule_id", unique=True),
        Index("ix_firewall_rules_active_type", "is_active", "rule_type"),
        Index("ix_firewall_rules_category", "category"),
        CheckConstraint(
            "rule_type IN ('REGEX', 'KEYWORD', 'EXCLUSION')",
            name="check_rule_type"
        ),
        CheckConstraint(
            "category IN ('JAILBREAK', 'PROMPT_LEAK', 'PII', 'SYSTEM_OVERRIDE')",
            name="check_category"
        ),
        CheckConstraint(
            "severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="check_severity"
        ),
    )


class SystemMetric(Base):
    __tablename__ = "system_metrics"

    id = Column(Integer, primary_key=True, autoincrement=True)
    bucket_start = Column(DateTime(timezone=True), nullable=False)
    total_requests = Column(Integer, default=0, nullable=False)
    blocked_requests = Column(Integer, default=0, nullable=False)
    layer_1_blocks = Column(Integer, default=0, nullable=False)
    layer_2_blocks = Column(Integer, default=0, nullable=False)
    layer_3_blocks = Column(Integer, default=0, nullable=False)
    output_blocks = Column(Integer, default=0, nullable=False)
    avg_latency_ms = Column(Float, default=0.0, nullable=False)
    p95_latency_ms = Column(Float, default=0.0, nullable=False)

    __table_args__ = (
        Index("ix_system_metrics_bucket_start_desc", bucket_start.desc(), unique=True),
    )


class BlockedClient(Base):
    """Client IPs an administrator has blocked. The gateway refuses their requests."""

    __tablename__ = "blocked_clients"

    id = Column(Integer, primary_key=True, autoincrement=True)
    client_ip = Column(String, unique=True, nullable=False)
    reason = Column(Text, nullable=True)
    blocked_by = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)


_AUDIT_ACTIONS_SQL = (
    "action IN ('RULE_CREATED', 'RULE_UPDATED', 'RULE_DELETED', 'THRESHOLD_CHANGED', "
    "'LOG_DELETED', 'IP_BLOCKED', 'IP_UNBLOCKED')"
)


class AdminAuditLog(Base):
    __tablename__ = "admin_audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    admin_user = Column(String, nullable=False)
    action = Column(String, nullable=False)        
    target_rule_id = Column(String, nullable=True)
    change_details = Column(JSONB, nullable=True)

    __table_args__ = (
        Index("ix_admin_audit_logs_timestamp_desc", timestamp.desc()),
        CheckConstraint(
            _AUDIT_ACTIONS_SQL,
            name="check_audit_action"
        ),
    )


async def init_schema(engine) -> None:
    """Asynchronously initialize database schema (idempotent create_all)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # create_all never alters an existing table, so databases created before the
        # LOG_DELETED / IP_BLOCKED / IP_UNBLOCKED audit actions existed still carry the
        # old CHECK constraint. Widen it once (a no-op when it is already current).
        current = (
            await conn.execute(
                text("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'check_audit_action'")
            )
        ).scalar_one_or_none()
        if current is not None and "IP_BLOCKED" not in current:
            await conn.execute(text("ALTER TABLE admin_audit_logs DROP CONSTRAINT check_audit_action"))
            await conn.execute(
                text(f"ALTER TABLE admin_audit_logs ADD CONSTRAINT check_audit_action CHECK ({_AUDIT_ACTIONS_SQL})")
            )
