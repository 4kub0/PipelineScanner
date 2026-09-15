"""PipelineGuard security rule definitions."""

from pipelineguard.rules.base import BaseRule
from pipelineguard.rules.rule1_pr_target import PullRequestTargetPoisoningRule

__all__ = ["BaseRule", "PullRequestTargetPoisoningRule"]
