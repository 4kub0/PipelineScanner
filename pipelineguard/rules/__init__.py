"""PipelineGuard security rule definitions."""

from pipelineguard.rules.base import BaseRule
from pipelineguard.rules.rule1_pr_target import PullRequestTargetPoisoningRule
from pipelineguard.rules.rule2_script_injection import ScriptInjectionRule
from pipelineguard.rules.rule3_permissions import OverprivilegedPermissionsRule
from pipelineguard.rules.rule4_unpinned_actions import UnpinnedActionRule

__all__ = [
    "BaseRule",
    "PullRequestTargetPoisoningRule",
    "ScriptInjectionRule",
    "OverprivilegedPermissionsRule",
    "UnpinnedActionRule",
]
