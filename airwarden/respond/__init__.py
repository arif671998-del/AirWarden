"""Approved, verified response layer.

No change ever reaches the network without operator approval, and every applied
fix is re-checked. Actions run on the operator's own OpenWrt router via UCI over
SSH; a dry-run mode (default) records the exact commands without executing them,
so the system is safe to demo without hardware."""
from .approval import ApprovalManager  # noqa: F401
from .openwrt import OpenWrtRouter, ResponseResult  # noqa: F401
