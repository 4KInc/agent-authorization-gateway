"""Discovery Engine (Agent Search) RAG tool for the Policy Auditor Agent.

Searches the compliance PDF corpus and returns extractive answers
(verbatim passages from source documents) along with source attribution.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, asdict
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ComplianceCitation:
    source_document: str
    extractive_answer: str
    relevance_score: float
    page_number: Optional[int] = None


class ComplianceSearcher:
    def __init__(self, project_id: str, data_store_id: str,
                 location: str = "global", engine_id: str | None = None):
        self.project_id = project_id
        self.data_store_id = data_store_id
        self.location = location
        self.engine_id = engine_id
        self._client = None

    @property
    def client(self):
        if self._client is None:
            from google.cloud import discoveryengine_v1 as discoveryengine
            self._client = discoveryengine.SearchServiceClient()
        return self._client

    def search(self, query: str, page_size: int = 5) -> List[ComplianceCitation]:
        """Search the compliance corpus. Returns extractive citations."""
        from google.cloud import discoveryengine_v1 as discoveryengine

        if self.engine_id:
            serving_config = (
                f"projects/{self.project_id}/locations/{self.location}"
                f"/collections/default_collection"
                f"/engines/{self.engine_id}"
                f"/servingConfigs/default_config"
            )
        else:
            serving_config = (
                f"projects/{self.project_id}/locations/{self.location}"
                f"/dataStores/{self.data_store_id}"
                f"/servingConfigs/default_config"
            )

        content_search_spec = discoveryengine.SearchRequest.ContentSearchSpec(
            extractive_content_spec=(
                discoveryengine.SearchRequest
                .ContentSearchSpec.ExtractiveContentSpec(
                    max_extractive_answer_count=1,
                    max_extractive_segment_count=0,
                )
            )
        )

        request = discoveryengine.SearchRequest(
            serving_config=serving_config,
            query=query,
            page_size=page_size,
            content_search_spec=content_search_spec,
        )

        try:
            response = self.client.search(request)
        except Exception as e:
            logger.warning("Discovery Engine search failed: %s", e)
            return []

        citations: List[ComplianceCitation] = []
        for result in response.results:
            doc = result.document
            derived = dict(doc.derived_struct_data) if doc.derived_struct_data else {}
            extractive = derived.get("extractive_answers", [])
            if not extractive:
                # Try snippets as fallback
                snippets = derived.get("snippets", [])
                if snippets:
                    first = snippets[0] if isinstance(snippets[0], dict) else dict(snippets[0])
                    citations.append(ComplianceCitation(
                        source_document=derived.get("link", doc.id).split("/")[-1],
                        extractive_answer=first.get("snippet", ""),
                        relevance_score=0.0,
                    ))
                continue

            first = extractive[0]
            if isinstance(first, dict):
                content = first.get("content", "")
                page = first.get("pageNumber")
            else:
                ev = dict(first)
                content = ev.get("content", "")
                page = ev.get("pageNumber")

            link = derived.get("link", "")
            source = link.split("/")[-1] if link else doc.id

            citations.append(ComplianceCitation(
                source_document=source,
                extractive_answer=content,
                relevance_score=0.0,
                page_number=int(page) if page else None,
            ))

        logger.info("Compliance search query=%r returned=%d citations", query, len(citations))
        return citations


def make_adk_search_tool(searcher: ComplianceSearcher):
    """Wrap the searcher as an ADK FunctionTool."""
    from google.adk.tools import FunctionTool

    def search_compliance_guidelines(query: str) -> str:
        """Search internal compliance documents (OWASP NHI Top 10, NIST AI
        RMF, NIST SP 800-53) for guidance relevant to the query. Returns
        verbatim passages with source attribution.

        Use this when auditing a receipt to find natural-language policy
        that applies to the action, resource, agent, or decision.
        """
        try:
            citations = searcher.search(query, page_size=3)
        except Exception as e:
            logger.warning("Compliance search failed: %s", e)
            return f"[search_unavailable: {e}]"

        if not citations:
            return "[no_relevant_compliance_guidance_found]"

        parts = []
        for c in citations:
            page_str = f", page {c.page_number}" if c.page_number else ""
            parts.append(
                f"Source: {c.source_document}{page_str}\n"
                f"Passage: \"{c.extractive_answer}\""
            )
        return "\n\n".join(parts)

    return FunctionTool(search_compliance_guidelines)
