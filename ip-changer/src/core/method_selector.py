"""Method selector engine for connection profile evaluation and selection.

Provides deterministic, transparent connection profile selection based on
traffic scope, rotation frequency, capability feasibility, priority weighting,
and manual override directives.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from src.core.capability_registry import CapabilityRegistry
from src.core.event_bus import EventBus
from src.models.app_settings import AppSettings
from src.models.connection_profile import ConnectionProfile, ConnectionType, TrafficScope

logger = logging.getLogger(__name__)


@dataclass
class SelectionResult:
    """Outcome of profile selection evaluation."""
    selected_profile: Optional[ConnectionProfile]
    reason: str
    rejected_profiles: List[Tuple[ConnectionProfile, str]] = field(default_factory=list)
    selection_policy: str = "Deterministic capability and priority matching"


class MethodSelector:
    """Evaluates and selects the optimal connection profile."""

    def __init__(
        self,
        capability_registry: CapabilityRegistry,
        settings: AppSettings,
        event_bus: EventBus,
    ) -> None:
        """Initialize method selector.

        Args:
            capability_registry: Registry of connection method capabilities.
            settings: Master application settings.
            event_bus: System event bus.
        """
        self._capabilities = capability_registry
        self._settings = settings
        self._event_bus = event_bus

    def _evaluate_profile(
        self,
        profile: ConnectionProfile,
        interval: int,
        scope: TrafficScope,
    ) -> Tuple[bool, str]:
        """Perform thorough feasibility and validation checks on a single profile.

        Args:
            profile: Profile to evaluate.
            interval: Desired rotation interval in seconds.
            scope: Desired traffic routing scope.

        Returns:
            Tuple of (is_viable: bool, explanation: str).
        """
        if not profile.enabled:
            return False, f"Profile '{profile.name}' is currently disabled."

        if not profile.is_valid():
            return False, f"Profile '{profile.name}' failed structural validation."

        feasible, reason = self._capabilities.is_feasible(profile, interval, scope)
        if not feasible:
            return False, reason

        return True, "Profile is feasible and valid."

    def select(
        self,
        profiles: List[ConnectionProfile],
        interval: int,
        scope: TrafficScope,
        manual_override_id: Optional[str] = None,
    ) -> SelectionResult:
        """Deterministically select the best matching connection profile.

        Selection policy:
        1. If manual_override_id is provided, look up that profile. If viable, select it.
        2. Filter to enabled profiles only.
        3. Reject profiles that fail feasibility (interval, scope, dependencies).
        4. When SYSTEM_WIDE scope is requested, prefer VPN tunnel profiles.
        5. Sort candidates by priority (descending) and profile name (ascending).
        6. Return the highest-ranked profile.

        Args:
            profiles: Available candidate connection profiles.
            interval: Requested rotation interval in seconds.
            scope: Target traffic routing scope.
            manual_override_id: Specific profile ID requested by the user.

        Returns:
            SelectionResult describing the chosen profile and all evaluations.
        """
        rejected: List[Tuple[ConnectionProfile, str]] = []

        # 1. Manual override handling
        if manual_override_id:
            target_profile = next((p for p in profiles if p.id == manual_override_id), None)
            if target_profile:
                viable, reason = self._evaluate_profile(target_profile, interval, scope)
                if viable:
                    return SelectionResult(
                        selected_profile=target_profile,
                        reason=f"Selected profile '{target_profile.name}' via explicit manual override.",
                        rejected_profiles=rejected,
                        selection_policy="Manual override",
                    )
                rejected.append((target_profile, f"Manual override rejected: {reason}"))
            else:
                logger.warning("Manual override ID '%s' was not found in profile list", manual_override_id)

        # 2. Evaluate all candidates
        viable_candidates: List[ConnectionProfile] = []
        for profile in profiles:
            if manual_override_id and profile.id == manual_override_id:
                continue  # Already evaluated above

            viable, reason = self._evaluate_profile(profile, interval, scope)
            if viable:
                viable_candidates.append(profile)
            else:
                rejected.append((profile, reason))

        if not viable_candidates:
            return SelectionResult(
                selected_profile=None,
                reason="No enabled connection profiles meet the interval and traffic scope constraints.",
                rejected_profiles=rejected,
                selection_policy="Deterministic capability and priority matching",
            )

        # 3. Preference ranking
        vpn_types = {
            ConnectionType.VPN_OPENVPN,
            ConnectionType.VPN_WIREGUARD,
            ConnectionType.VPN_SYSTEM,
        }

        def candidate_sort_key(p: ConnectionProfile) -> Tuple[int, int, str]:
            # If SYSTEM_WIDE, strongly prioritize VPN endpoints
            scope_pref = 1 if (scope == TrafficScope.SYSTEM_WIDE and p.connection_type in vpn_types) else 0
            # Higher priority number first
            return (scope_pref, p.priority, p.name)

        # Sort candidates descending by scope preference and priority, ascending by name
        viable_candidates.sort(
            key=lambda p: (
                1 if (scope == TrafficScope.SYSTEM_WIDE and p.connection_type in vpn_types) else 0,
                p.priority,
            ),
            reverse=True,
        )

        chosen = viable_candidates[0]
        reason_text = (
            f"Selected '{chosen.name}' ({chosen.connection_type.value}) as highest-priority "
            f"feasible profile (priority={chosen.priority}) out of {len(viable_candidates)} candidate(s)."
        )

        return SelectionResult(
            selected_profile=chosen,
            reason=reason_text,
            rejected_profiles=rejected,
            selection_policy="Deterministic capability and priority matching",
        )

    def get_selection_explanation(self, result: SelectionResult) -> str:
        """Produce a human-readable diagnostic report of the selection outcome.

        Args:
            result: SelectionResult to explain.

        Returns:
            Formatted explanation text suitable for logs or UI display.
        """
        lines = [
            f"Selection Policy: {result.selection_policy}",
            f"Result: {result.reason}",
        ]

        if result.selected_profile:
            lines.append(
                f"Active Profile: '{result.selected_profile.name}' "
                f"[{result.selected_profile.connection_type.value}] "
                f"Endpoint: {result.selected_profile.host}:{result.selected_profile.port}"
            )
        else:
            lines.append("Active Profile: None")

        if result.rejected_profiles:
            lines.append(f"Rejected Profiles ({len(result.rejected_profiles)}):")
            for prof, rejection_reason in result.rejected_profiles:
                lines.append(f"  - {prof.name} ({prof.connection_type.value}): {rejection_reason}")

        return "\n".join(lines)
