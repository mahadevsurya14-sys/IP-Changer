"""About Tab View for IP Changer.

Provides application metadata, author attribution, supported platforms,
license terms, and essential privacy/anonymity disclaimers.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)


class AboutWidget(QWidget):
    """About tab presenting metadata and disclaimers."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self) -> None:
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(18)

        # Header Card
        header_card = QFrame()
        header_card.setStyleSheet(
            "background-color: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 18px;"
        )
        h_layout = QVBoxLayout(header_card)
        h_layout.setSpacing(8)

        lbl_app_name = QLabel("IP Changer")
        title_font = QFont()
        title_font.setPointSize(22)
        title_font.setBold(True)
        lbl_app_name.setFont(title_font)
        lbl_app_name.setStyleSheet("color: #00d4ff;")

        lbl_version = QLabel("Version 1.0.0  •  Author: Mahaduuu")
        lbl_version.setStyleSheet("color: #94a3b8; font-size: 14px; font-weight: 600;")

        lbl_desc = QLabel(
            "A high-reliability cross-platform desktop application designed to manage, verify, "
            "and automatically rotate public IP addresses through authorized proxy and VPN connections."
        )
        lbl_desc.setWordWrap(True)
        lbl_desc.setStyleSheet("color: #e2e8f0; font-size: 13px; line-height: 1.4;")

        h_layout.addWidget(lbl_app_name)
        h_layout.addWidget(lbl_version)
        h_layout.addWidget(lbl_desc)
        layout.addWidget(header_card)

        # Key Features & Platforms Card
        feat_card = QFrame()
        feat_card.setStyleSheet(
            "background-color: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 16px;"
        )
        f_layout = QVBoxLayout(feat_card)
        f_layout.setSpacing(8)

        lbl_feat_title = QLabel("Supported Platforms & Protocols")
        lbl_feat_title.setStyleSheet("color: #00d4ff; font-weight: bold; font-size: 14px;")
        f_layout.addWidget(lbl_feat_title)

        features_text = (
            "• <b>Operating Systems:</b> Windows 11 & Kali Linux (Debian-based)<br/>"
            "• <b>Protocols:</b> HTTP / HTTPS, SOCKS5 (with remote DNS), System Native VPN, OpenVPN, WireGuard<br/>"
            "• <b>Core Engine:</b> Deterministic state machine, dual-stack IP verification, exponential backoff<br/>"
            "• <b>Security:</b> OS Keyring credential storage, kill switch leak mitigation, credential log scrubbing"
        )
        lbl_features = QLabel(features_text)
        lbl_features.setStyleSheet("color: #cbd5e1; font-size: 13px;")
        lbl_features.setTextFormat(Qt.RichText)
        f_layout.addWidget(lbl_features)
        layout.addWidget(feat_card)

        # Important Security Disclaimer Card
        disclaimer_card = QFrame()
        disclaimer_card.setStyleSheet(
            "background-color: #450a0a; border: 1px solid #dc2626; border-radius: 8px; padding: 16px;"
        )
        d_layout = QVBoxLayout(disclaimer_card)
        d_layout.setSpacing(8)

        lbl_disc_title = QLabel("⚠️ Important Security & Privacy Notice")
        lbl_disc_title.setStyleSheet("color: #fca5a5; font-weight: bold; font-size: 14px;")
        d_layout.addWidget(lbl_disc_title)

        disc_text = (
            "<b>IP Rotation is NOT Complete Anonymity:</b><br/>"
            "Changing your public IP address disguises your network endpoint from basic IP-based rate limiting "
            "and geolocation lookups. However, browser fingerprinting, cookies, TLS characteristics, OS telemetry, "
            "and upstream proxy logs can still identify or trace traffic. For operations requiring rigorous anonymity, "
            "use dedicated privacy platforms such as Tor or Tails OS."
        )
        lbl_disc = QLabel(disc_text)
        lbl_disc.setWordWrap(True)
        lbl_disc.setStyleSheet("color: #fee2e2; font-size: 13px; line-height: 1.4;")
        lbl_disc.setTextFormat(Qt.RichText)
        d_layout.addWidget(lbl_disc)
        layout.addWidget(disclaimer_card)

        # License Info
        license_card = QFrame()
        license_card.setStyleSheet(
            "background-color: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 14px;"
        )
        l_layout = QVBoxLayout(license_card)
        lbl_lic_title = QLabel("License: MIT")
        lbl_lic_title.setStyleSheet("color: #94a3b8; font-weight: bold; font-size: 13px;")
        lbl_lic_body = QLabel(
            "Copyright (c) 2026 Mahaduuu. Released under the terms of the MIT License."
        )
        lbl_lic_body.setStyleSheet("color: #64748b; font-size: 12px;")
        l_layout.addWidget(lbl_lic_title)
        l_layout.addWidget(lbl_lic_body)
        layout.addWidget(license_card)

        layout.addStretch()

        scroll.setWidget(container)
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.addWidget(scroll)
