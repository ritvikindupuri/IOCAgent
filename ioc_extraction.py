"""
IOC Extraction Specialist

This script implements a fully adaptive IOC (Indicator of Compromise) extraction and
analysis framework for cybersecurity workflows. Its purpose is to extract structured
security indicators from raw text while avoiding hardcoded threat assumptions that can
become stale as attacker behavior, SIEM platforms, and threat intelligence sources evolve.

What this code does:

1. Format-Based IOC Extraction
   - Extracts common IOC types from raw security text using regex patterns:
     IPv4, IPv6, domains, URLs, MD5, SHA1, SHA256, and email addresses.
   - Uses format-based identification only, rather than assuming something is malicious
     simply because it matches a known pattern.
   - Filters RFC-defined private IP ranges so internal/private addresses are not mixed
     with public-facing indicators.

2. Dynamic Threat Analysis Preparation
   - Builds structured prompts for LLM-driven or threat-intelligence-driven analysis.
   - Instead of hardcoding domain reputation, malware attribution, or threat actor links,
     the code prepares IOC data for real-time contextual analysis using current sources.
   - This makes the design more flexible for modern SOC, IR, and threat hunting pipelines.

3. Dynamic MITRE ATT&CK Mapping
   - Prepares IOC context for mapping against the latest MITRE ATT&CK techniques and
     sub-techniques without relying on static rule mappings.
   - This helps the system stay adaptable as ATT&CK evolves over time.

4. Adaptive SIEM Query Generation
   - Supports generating SIEM hunting logic in a dynamic way.
   - If no platform configuration is provided, the code prepares a prompt for generating
     current, optimized queries for platforms like Splunk, CrowdStrike, Elastic, and
     Microsoft Sentinel.
   - If configurations are provided, it can build queries directly from platform-specific
     field mappings and templates.

5. Adaptive Validation and Enrichment
   - Prepares IOCs for live validation against current reputation services and threat
     intelligence sources rather than relying on static allowlists, blocklists, or
     embedded assumptions.
   - Designed to reduce stale reputation logic and improve relevance in active incidents.

6. Entropy and Contextual String Analysis
   - Calculates Shannon entropy for strings and prepares them for contextual analysis,
     which can help evaluate suspicious domains, generated strings, or possible DGA-like
     behavior in a dynamic manner.

7. Dynamic Reporting Workflow
   - Produces structured result objects that can be passed into an LLM or external
     enrichment system to generate a professional incident report, including:
       • executive summary
       • IOC findings
       • threat context
       • MITRE ATT&CK mappings
       • recommendations
       • SIEM hunting guidance

Primary use cases:
- Security Operations Center (SOC) triage
- Incident response investigations
- Threat hunting preparation
- Threat intelligence enrichment pipelines
- IOC parsing from reports, alerts, logs, or analyst notes
- Building AI-assisted security analysis systems

Overall, this code is designed as an adaptive cybersecurity foundation that separates
basic IOC extraction from higher-level threat reasoning, allowing the analysis layer
to stay current with the evolving threat landscape.
"""

import re
import json
import hashlib
import base64
import math
from typing import Dict, List, Set, Optional
from urllib.parse import urlparse
from collections import Counter

class IOCExtractionSpecialist:
    """
    IOC Extraction Specialist - Fully dynamic cybersecurity tool that adapts to
    the evolving threat landscape without hardcoded assumptions.
    """
    
    def __init__(self):
        # Core regex patterns (these are format-based, not threat-based)
        self.patterns = {
            'ipv4': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            'domain': r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}\b',
            'url': r'https?://[^\s<>"]+',
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        }
        
        # RFC-defined private IP ranges (these are static by internet standards)
        self.private_ip_patterns = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[01])\.',
            r'^192\.168\.',
            r'^127\.',
            r'^169\.254\.',
            r'^0\.',
            r'^255\.'
        ]

    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extract IOCs using format-based patterns only"""
        iocs = {}
        
        for ioc_type, pattern in self.patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            unique_matches = list(set(matches))
            
            if ioc_type == 'ipv4':
                # Only filter RFC private ranges - no assumptions about legitimacy
                unique_matches = [ip for ip in unique_matches if not self.is_private_ip(ip)]
            
            iocs[ioc_type] = unique_matches
        
        return iocs

    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is in RFC-defined private ranges"""
        return any(re.match(pattern, ip) for pattern in self.private_ip_patterns)

    def dynamic_threat_analysis(self, iocs: Dict[str, List[str]], context: str = "") -> Dict:
        """
        Use LLM and threat intelligence to dynamically analyze IOCs.
        No hardcoded assumptions about what's malicious.
        """
        analysis_prompt = f"""
        Analyze these extracted IOCs in the context of current threat intelligence:
        
        IOCs: {json.dumps(iocs, indent=2)}
        Context: {context}
        
        For each IOC, provide:
        1. Current threat reputation (check latest feeds)
        2. Confidence level based on multiple sources
        3. Associated threat actors (if any)
        4. Campaign attribution (if applicable)
        5. Recommended actions
        
        Use current threat intelligence, not historical assumptions.
        """
        
        # This would call the LLM tool for dynamic analysis
        return {
            "requires_llm_analysis": True,
            "prompt": analysis_prompt,
            "note": "Dynamic analysis prevents hardcoded threat assumptions"
        }

    def dynamic_mitre_mapping(self, iocs: Dict[str, List[str]], context: str = "") -> Dict:
        """
        Dynamically map IOCs to current MITRE ATT&CK framework using LLM analysis.
        No hardcoded technique mappings.
        """
        mitre_prompt = f"""
        Map these IOCs to the current MITRE ATT&CK framework:
        
        IOCs: {json.dumps(iocs, indent=2)}
        Context: {context}
        
        Requirements:
        1. Use the latest MITRE ATT&CK version
        2. Consider current threat landscape
        3. Analyze IOC relationships and patterns
        4. Map to specific techniques and sub-techniques
        5. Provide confidence scores
        
        Return JSON format: {{"technique_id": ["description", confidence_score]}}
        """
        
        return {
            "requires_llm_analysis": True,
            "prompt": mitre_prompt,
            "note": "Dynamic MITRE mapping adapts to evolving framework"
        }

    def generate_adaptive_siem_queries(self, iocs: Dict[str, List[str]], platform_configs: Dict = None) -> Dict[str, List[str]]:
        """
        Generate SIEM queries that adapt to different platform versions and configurations.
        No hardcoded field names or query structures.
        """
        if not platform_configs:
            # Use LLM to determine current platform capabilities
            config_prompt = f"""
            Generate optimized SIEM queries for these IOCs across major platforms:
            
            IOCs: {json.dumps(iocs, indent=2)}
            
            For each platform (Splunk, CrowdStrike, Elastic, Sentinel):
            1. Use current platform capabilities
            2. Optimize for performance
            3. Include behavioral detection patterns
            4. Account for different log source formats
            5. Add time-based correlation where relevant
            
            Adapt queries to current platform versions and best practices.
            """
            
            return {
                "requires_llm_analysis": True,
                "prompt": config_prompt,
                "note": "Adaptive query generation prevents outdated syntax"
            }
        
        # If configs provided, generate accordingly
        return self._generate_platform_queries(iocs, platform_configs)

    def _generate_platform_queries(self, iocs: Dict[str, List[str]], configs: Dict) -> Dict[str, List[str]]:
        """Generate queries based on provided platform configurations"""
        queries = {}
        
        for platform, config in configs.items():
            queries[platform] = []
            field_mappings = config.get('field_mappings', {})
            
            for ioc_type, ioc_list in iocs.items():
                if ioc_list and ioc_type in field_mappings:
                    for ioc in ioc_list:
                        query_template = config.get('query_templates', {}).get(ioc_type)
                        if query_template:
                            queries[platform].append(query_template.format(
                                field=field_mappings[ioc_type],
                                value=ioc
                            ))
        
        return queries

    def adaptive_ioc_validation(self, iocs: Dict[str, List[str]]) -> Dict:
        """
        Validate IOCs using current threat intelligence and reputation services.
        No hardcoded reputation assumptions.
        """
        validation_prompt = f"""
        Validate these IOCs using current threat intelligence sources:
        
        IOCs: {json.dumps(iocs, indent=2)}
        
        For each IOC:
        1. Check current reputation across multiple sources
        2. Verify format and validity
        3. Assess confidence based on source reliability
        4. Identify potential false positives
        5. Provide enrichment data (geolocation, WHOIS, etc.)
        
        Use real-time data, not cached assumptions.
        """
        
        return {
            "requires_threat_intel_lookup": True,
            "prompt": validation_prompt,
            "note": "Real-time validation prevents stale reputation data"
        }

    def calculate_dynamic_entropy(self, string: str) -> Dict:
        """Calculate entropy with contextual analysis"""
        if not string:
            return {"entropy": 0, "analysis": "Empty string"}
        
        counts = Counter(string)
        length = len(string)
        entropy = -sum(count/length * math.log2(count/length) for count in counts.values())
        
        # Dynamic thresholds based on string type and context
        analysis_prompt = f"""
        Analyze this string's entropy in cybersecurity context:
        
        String: {string}
        Calculated Entropy: {entropy}
        Length: {length}
        Character Distribution: {dict(counts)}
        
        Determine:
        1. Is this entropy suspicious for this string type?
        2. What are current DGA detection thresholds?
        3. How does this compare to legitimate vs malicious patterns?
        4. Confidence level of assessment
        """
        
        return {
            "entropy": entropy,
            "requires_contextual_analysis": True,
            "prompt": analysis_prompt
        }

    def process_text_dynamically(self, input_text: str, context: str = "") -> Dict:
        """
        Main processing function that uses dynamic analysis throughout.
        No hardcoded threat assumptions.
        """
        # Extract IOCs (format-based only)
        extracted_iocs = self.extract_iocs(input_text)
        
        # All analysis is dynamic and context-aware
        results = {
            'extracted_iocs': extracted_iocs,
            'dynamic_analysis': self.dynamic_threat_analysis(extracted_iocs, context),
            'mitre_mapping': self.dynamic_mitre_mapping(extracted_iocs, context),
            'siem_queries': self.generate_adaptive_siem_queries(extracted_iocs),
            'validation': self.adaptive_ioc_validation(extracted_iocs),
            'processing_note': 'All analysis is dynamic and adapts to current threat landscape'
        }
        
        return results

    def generate_dynamic_report(self, results: Dict, context: str = "") -> str:
        """Generate report using LLM for dynamic formatting and insights"""
        report_prompt = f"""
        Generate a comprehensive IOC analysis report:
        
        Results: {json.dumps(results, indent=2)}
        Context: {context}
        
        Include:
        1. Executive summary with current threat assessment
        2. IOC analysis with confidence levels
        3. MITRE ATT&CK mapping with latest techniques
        4. Actionable recommendations
        5. SIEM hunting queries optimized for current platforms
        6. Timeline analysis if applicable
        
        Format professionally and adapt content to current threat landscape.
        """
        
        return {
            "requires_llm_generation": True,
            "prompt": report_prompt,
            "note": "Dynamic reporting adapts to current threats and context"
        }


def create_adaptive_extractor():
    """Factory function to create a fully adaptive IOC extractor"""
    return IOCExtractionSpecialist()


# Example usage showing dynamic approach
def main():
    """Example showing fully dynamic IOC analysis"""
    extractor = create_adaptive_extractor()
    
    sample_text = """
    Security incident detected: Communication to 203.0.113.5
    Domain contacted: suspicious-domain.example
    File hash observed: d41d8cd98f00b204e9800998ecf8427e
    """
    
    context = "Enterprise network security incident - potential APT activity"
    
    # Process with full dynamic analysis
    results = extractor.process_text_dynamically(sample_text, context)
    
    print("Dynamic IOC Analysis Results:")
    print(json.dumps(results, indent=2))
    
    return results


if __name__ == "__main__":
    results = main()
