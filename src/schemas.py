"""Pydantic schemas for MCP-Vul data structures."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


# === Enums ===

class Verdict(str, Enum):
    """Possible analysis verdicts."""
    VULNERABLE = "VULNERABLE"
    SAFE = "SAFE"
    NOT_ENOUGH_EVIDENCE = "NOT_ENOUGH_EVIDENCE"


# === AST Server Schemas ===

class Parameter(BaseModel):
    """Function parameter."""
    name: str
    type: str


class LocalVariable(BaseModel):
    """Local variable declaration."""
    name: str
    type: str
    line: int


class FunctionCall(BaseModel):
    """A function call found in the code."""
    name: str
    arguments: list[str] = Field(default_factory=list)
    line: int
    is_risky: bool = False


class RiskySink(BaseModel):
    """A potentially dangerous function call (sink)."""
    function: str
    line: int
    arguments: list[str] = Field(default_factory=list)


class ASTAnalysisInput(BaseModel):
    """Input for AST analysis."""
    source_code: str


class ASTAnalysisOutput(BaseModel):
    """Output from AST analysis."""
    function_name: Optional[str] = None
    parameters: list[Parameter] = Field(default_factory=list)
    local_variables: list[LocalVariable] = Field(default_factory=list)
    function_calls: list[FunctionCall] = Field(default_factory=list)
    risky_sinks: list[RiskySink] = Field(default_factory=list)
    parse_error: Optional[str] = None


# === Static Analysis Server Schemas ===

class AnalysisFinding(BaseModel):
    """A finding from static analysis."""
    checker: str
    category: str
    message: str
    line: int
    column: int = 0
    sink: Optional[str] = None
    taint_source: Optional[str] = None


class StaticAnalysisInput(BaseModel):
    """Input for static analysis."""
    source_code: str
    context: Optional[str] = None


class StaticAnalysisOutput(BaseModel):
    """Output from static analysis."""
    findings: list[AnalysisFinding] = Field(default_factory=list)
    analysis_successful: bool = True
    error: Optional[str] = None


# === CWE Knowledge Server Schemas ===

class CWEExample(BaseModel):
    """Example vulnerable and safe code patterns."""
    vulnerable: str
    safe: str


class CWEKnowledgeInput(BaseModel):
    """Input for CWE knowledge lookup."""
    sink_function: str
    query_type: str = "safety_checks"  # safety_checks | vulnerability_pattern | description


class CWEKnowledgeOutput(BaseModel):
    """Output from CWE knowledge lookup."""
    cwe_id: str = "CWE-120"
    sink_function: str
    required_safety_checks: list[str] = Field(default_factory=list)
    common_patterns: list[str] = Field(default_factory=list)
    description: str = ""
    examples: list[CWEExample] = Field(default_factory=list)


# === Evidence & Agent Schemas ===

class Evidence(BaseModel):
    """A piece of evidence from a tool."""
    tool: str
    finding: str
    citation: str


class OrchestratorHypothesis(BaseModel):
    """The orchestrator's hypothesis about the code."""
    hypothesis: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[Evidence] = Field(default_factory=list)
    reasoning: str


class ValidationCheck(BaseModel):
    """A single validation check result."""
    present: bool
    citation: str


class JudgeValidation(BaseModel):
    """The judge's validation of the hypothesis."""
    dangerous_sink: ValidationCheck
    data_flow: ValidationCheck
    missing_checks: ValidationCheck


class JudgeVerdict(BaseModel):
    """The judge's final verdict."""
    verdict: Verdict
    validation: JudgeValidation
    final_reasoning: str


# === Pipeline Schemas ===

class AnalysisResult(BaseModel):
    """Complete analysis result for a function."""
    function_name: str
    source_code: str
    ast_output: Optional[ASTAnalysisOutput] = None
    static_output: Optional[StaticAnalysisOutput] = None
    cwe_output: Optional[CWEKnowledgeOutput] = None
    orchestrator_hypothesis: Optional[OrchestratorHypothesis] = None
    judge_verdict: Optional[JudgeVerdict] = None
    final_verdict: Verdict = Verdict.NOT_ENOUGH_EVIDENCE
    ground_truth: Optional[bool] = None  # True = vulnerable, False = safe


class ExperimentResult(BaseModel):
    """Results from running an experiment."""
    total_samples: int
    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    not_enough_evidence: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    evidence_backed_rate: float = 0.0
    hallucination_rate: float = 0.0
