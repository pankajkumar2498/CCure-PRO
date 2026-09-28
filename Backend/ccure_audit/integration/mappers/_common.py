"""Helpers every mapper shares."""

from __future__ import annotations

from typing import Any, Dict, Optional, Type, TypeVar

from pydantic import BaseModel, ValidationError

from ccure_audit.integration.errors import MappingError
from ccure_contracts.common.v1.envelope import (
    CcureControlRefV1,
    CcureFrameworkRefV1,
    CcureMeasuredValueV1,
)
from ccure_contracts.common.v1.vocabulary import ValueStatus

M = TypeVar("M", bound=BaseModel)


def build(model: Type[M], data: Dict[str, Any], where: str) -> M:
    """
    Construct a contract model, turning a validation failure into
    :class:`MappingError` naming the object. The contract's own validators are
    the last word on what is expressible; a mapper never catches and repairs.
    """
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise MappingError(f"{where}: {exc}") from exc


def required(value: Optional[str], what: str, where: str) -> str:
    """A text value the contract requires and Audit must have stored."""
    text = (value or "").strip()
    if not text:
        raise MappingError(f"{where}: {what} is empty; the contract requires it")
    return text


def framework_ref(code: str, version: str, where: str) -> CcureFrameworkRefV1:
    return CcureFrameworkRefV1(
        code=required(code, "framework code", where),
        version=required(version, "framework version", where),
    )


def control_ref(code: str, version: str, number: str, where: str) -> CcureControlRefV1:
    return CcureControlRefV1(
        framework=framework_ref(code, version, where),
        control_id=required(number, "published control identifier", where),
    )


def measured(
    value: Optional[float], unit: Optional[str] = None
) -> CcureMeasuredValueV1:
    """An available value."""
    return CcureMeasuredValueV1(
        status=ValueStatus.AVAILABLE, value=float(value), unit=unit
    )


def unavailable(status: ValueStatus, reason: str) -> CcureMeasuredValueV1:
    """No value, and why — never a zero standing in for one."""
    return CcureMeasuredValueV1(status=status, reason=reason)
