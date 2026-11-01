"""Exact trust, sensitivity, and boundary-kind labels from the Master Blueprint."""

from enum import StrEnum


class TrustLabel(StrEnum):
    """Declared provenance class; not proof of authentication or authority."""

    T0_POLICY = "T0 POLICY"
    T1_OWNER_INTENT = "T1 OWNER_INTENT"
    T2_AUTH_METADATA = "T2 AUTH_METADATA"
    T3_DERIVED = "T3 DERIVED"
    T4_EXTERNAL = "T4 EXTERNAL"
    T5_UNKNOWN = "T5 UNKNOWN"


class SensitivityLabel(StrEnum):
    """Sensitivity class; missing or unknown values are rejected by contracts."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    PRIVATE = "PRIVATE"
    SECRET = "SECRET"


class BoundaryKind(StrEnum):
    """The two boundary classes represented by the §10 boundary envelope."""

    MODEL = "model"
    TOOL = "tool"
