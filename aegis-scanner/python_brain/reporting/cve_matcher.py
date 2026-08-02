"""
CVE Matcher for AEGIS security scanner.

This module matches verified zero-day behavioural patterns against known CVEs from 
NVD (National Vulnerability Database) databases for intelligence correlation.
"""

import json
import hashlib
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import re
from urllib.parse import urljoin
import asyncio
import aiohttp

logger = logging.getLogger(__name__)


class CVESeverity(Enum):
    """CVE severity levels based on CVSS scores."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CVEDetails:
    """Detailed information about a CVE."""
    cve_id: str
    description: str
    cvss_score: float
    severity: CVESeverity
    published_date: datetime
    modified_date: datetime
    references: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    scope: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None
    exploitability: Optional[str] = None
    remediation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnerabilityPattern:
    """A behavioural pattern extracted from verified vulnerabilities."""
    pattern_id: str
    pattern_type: str  # e.g., "buffer_overflow", "sql_injection", "auth_bypass"
    signature: str
    confidence: float
    description: str
    affected_components: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    protocol: Optional[str] = None
    port: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CVEMatch:
    """Result of matching a vulnerability pattern against CVEs."""
    pattern: VulnerabilityPattern
    matched_cve: CVEDetails
    match_score: float
    match_reason: str
    confidence: float
    timestamp: datetime = field(default_factory=datetime.now)


class NVDDatabase:
    """
    Interface to the NVD (National Vulnerability Database).
    
    Provides methods to query CVEs by various criteria including
    product, version, vulnerability type, and CVSS score.
    """
    
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_RATE_LIMIT = 30  # requests per minute (NVD limit)
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the NVD database interface.
        
        Args:
            api_key: Optional NVD API key for increased rate limits
        """
        self.api_key = api_key
        self.session: Optional[aiohttp.ClientSession] = None
        self.rate_limit_delay = 2.0 if api_key else 6.0  # seconds between requests
        self.last_request_time: Optional[datetime] = None
        self.cache: Dict[str, Any] = {}
        self.cache_ttl = timedelta(hours=1)
        
        logger.info("NVDDatabase initialized")
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def _make_request(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Make a rate-limited request to the NVD API.
        
        Args:
            params: Query parameters for the API request
            
        Returns:
            JSON response from the API
        """
        if not self.session:
            raise RuntimeError("Session not initialized. Use async context manager.")
        
        # Rate limiting
        if self.last_request_time:
            elapsed = datetime.now() - self.last_request_time
            if elapsed.total_seconds() < self.rate_limit_delay:
                await asyncio.sleep(self.rate_limit_delay - elapsed.total_seconds())
        
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        try:
            async with self.session.get(
                self.NVD_API_BASE,
                params=params,
                headers=headers
            ) as response:
                response.raise_for_status()
                self.last_request_time = datetime.now()
                return await response.json()
        except aiohttp.ClientError as e:
            logger.error(f"NVD API request failed: {e}")
            raise
    
    def _get_cache_key(self, params: Dict[str, Any]) -> str:
        """Generate a cache key from request parameters."""
        param_str = json.dumps(params, sort_keys=True)
        return hashlib.md5(param_str.encode()).hexdigest()
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cached data is still valid."""
        if cache_key not in self.cache:
            return False
        
        cached_time = self.cache[cache_key].get('timestamp')
        if not cached_time:
            return False
        
        return datetime.now() - cached_time < self.cache_ttl
    
    async def search_by_cpe(self, cpe_string: str) -> List[CVEDetails]:
        """
        Search for CVEs by CPE (Common Platform Enumeration) string.
        
        Args:
            cpe_string: CPE string to search for
            
        Returns:
            List of CVE details
        """
        cache_key = self._get_cache_key({'cpe': cpe_string})
        
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key]['data']
        
        params = {
            'cpeName': cpe_string,
            'resultsPerPage': 100
        }
        
        try:
            response = await self._make_request(params)
            cves = self._parse_cve_response(response)
            
            self.cache[cache_key] = {
                'data': cves,
                'timestamp': datetime.now()
            }
            
            return cves
        except Exception as e:
            logger.error(f"Failed to search by CPE: {e}")
            return []
    
    async def search_by_keyword(self, keyword: str) -> List[CVEDetails]:
        """
        Search for CVEs by keyword in description.
        
        Args:
            keyword: Keyword to search for
            
        Returns:
            List of CVE details
        """
        cache_key = self._get_cache_key({'keyword': keyword})
        
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key]['data']
        
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': 100
        }
        
        try:
            response = await self._make_request(params)
            cves = self._parse_cve_response(response)
            
            self.cache[cache_key] = {
                'data': cves,
                'timestamp': datetime.now()
            }
            
            return cves
        except Exception as e:
            logger.error(f"Failed to search by keyword: {e}")
            return []
    
    async def search_by_cvss(self, min_score: float, max_score: float = 10.0) -> List[CVEDetails]:
        """
        Search for CVEs by CVSS score range.
        
        Args:
            min_score: Minimum CVSS score
            max_score: Maximum CVSS score
            
        Returns:
            List of CVE details
        """
        cache_key = self._get_cache_key({'min_cvss': min_score, 'max_cvss': max_score})
        
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key]['data']
        
        params = {
            'cvssV3Severity': 'HIGH',  # Start with high severity
            'resultsPerPage': 100
        }
        
        try:
            response = await self._make_request(params)
            all_cves = self._parse_cve_response(response)
            
            # Filter by exact score range
            filtered_cves = [
                cve for cve in all_cves
                if min_score <= cve.cvss_score <= max_score
            ]
            
            self.cache[cache_key] = {
                'data': filtered_cves,
                'timestamp': datetime.now()
            }
            
            return filtered_cves
        except Exception as e:
            logger.error(f"Failed to search by CVSS: {e}")
            return []
    
    async def get_cve_by_id(self, cve_id: str) -> Optional[CVEDetails]:
        """
        Get detailed information about a specific CVE.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2023-1234)
            
        Returns:
            CVE details if found, None otherwise
        """
        cache_key = self._get_cache_key({'cve_id': cve_id})
        
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key]['data']
        
        params = {
            'cveId': cve_id
        }
        
        try:
            response = await self._make_request(params)
            cves = self._parse_cve_response(response)
            
            if cves:
                self.cache[cache_key] = {
                    'data': cves[0],
                    'timestamp': datetime.now()
                }
                return cves[0]
            
            return None
        except Exception as e:
            logger.error(f"Failed to get CVE by ID: {e}")
            return None
    
    def _parse_cve_response(self, response: Dict[str, Any]) -> List[CVEDetails]:
        """
        Parse NVD API response into CVE details.
        
        Args:
            response: Raw JSON response from NVD API
            
        Returns:
            List of parsed CVE details
        """
        cves = []
        
        try:
            vulns = response.get('vulnerabilities', [])
            
            for vuln in vulns:
                cve_item = vuln.get('cve', {})
                cve_id = cve_item.get('id', '')
                
                # Extract description
                descriptions = cve_item.get('descriptions', [])
                description = next(
                    (d.get('value', '') for d in descriptions if d.get('lang') == 'en'),
                    ''
                )
                
                # Extract metrics
                metrics = cve_item.get('metrics', {})
                cvss_data = metrics.get('cvssMetricV31', [])
                if not cvss_data:
                    cvss_data = metrics.get('cvssMetricV30', [])
                
                cvss_score = 0.0
                severity = CVESeverity.NONE
                attack_vector = None
                attack_complexity = None
                privileges_required = None
                user_interaction = None
                scope = None
                confidentiality_impact = None
                integrity_impact = None
                availability_impact = None
                
                if cvss_data:
                    cvss = cvss_data[0].get('cvssData', {})
                    cvss_score = cvss.get('baseScore', 0.0)
                    severity_str = cvss.get('baseSeverity', 'NONE')
                    severity = CVESeverity(severity_str.lower())
                    
                    attack_vector = cvss.get('attackVector')
                    attack_complexity = cvss.get('attackComplexity')
                    privileges_required = cvss.get('privilegesRequired')
                    user_interaction = cvss.get('userInteraction')
                    scope = cvss.get('scope')
                    confidentiality_impact = cvss.get('confidentialityImpact')
                    integrity_impact = cvss.get('integrityImpact')
                    availability_impact = cvss.get('availabilityImpact')
                
                # Extract dates
                published_str = cve_item.get('published', '')
                modified_str = cve_item.get('lastModified', '')
                
                try:
                    published_date = datetime.fromisoformat(published_str.replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    published_date = datetime.now()
                
                try:
                    modified_date = datetime.fromisoformat(modified_str.replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    modified_date = datetime.now()
                
                # Extract references
                references = cve_item.get('references', [])
                ref_urls = [r.get('url', '') for r in references]
                
                # Extract affected products (CPEs)
                configurations = cve_item.get('configurations', [])
                affected_products = []
                for config in configurations:
                    for node in config.get('nodes', []):
                        for cpe_match in node.get('cpeMatch', []):
                            cpe = cpe_match.get('criteria', '')
                            if cpe:
                                affected_products.append(cpe)
                
                cve_details = CVEDetails(
                    cve_id=cve_id,
                    description=description,
                    cvss_score=cvss_score,
                    severity=severity,
                    published_date=published_date,
                    modified_date=modified_date,
                    references=ref_urls,
                    affected_products=affected_products,
                    attack_vector=attack_vector,
                    attack_complexity=attack_complexity,
                    privileges_required=privileges_required,
                    user_interaction=user_interaction,
                    scope=scope,
                    confidentiality_impact=confidentiality_impact,
                    integrity_impact=integrity_impact,
                    availability_impact=availability_impact
                )
                
                cves.append(cve_details)
                
        except Exception as e:
            logger.error(f"Error parsing CVE response: {e}")
        
        return cves


class CVEMatcher:
    """
    Match verified zero-day behavioural patterns against known CVEs.
    
    Performs intelligence correlation by comparing vulnerability patterns
    discovered during scanning with known vulnerabilities in the NVD database.
    """
    
    def __init__(self, nvd_api_key: Optional[str] = None):
        """
        Initialize the CVE matcher.
        
        Args:
            nvd_api_key: Optional NVD API key for increased rate limits
        """
        self.nvd_db = NVDDatabase(api_key=nvd_api_key)
        self.pattern_database: List[VulnerabilityPattern] = []
        self.match_history: List[CVEMatch] = []
        
        # Pattern matching weights
        self.weights = {
            'signature_similarity': 0.4,
            'description_similarity': 0.3,
            'component_match': 0.2,
            'cvss_relevance': 0.1
        }
        
        logger.info("CVEMatcher initialized")
    
    async def initialize(self):
        """Initialize the CVE matcher and load pattern database."""
        logger.info("Initializing CVEMatcher")
        # Load pattern database (could be from file or predefined patterns)
        self._load_predefined_patterns()
    
    def _load_predefined_patterns(self):
        """Load predefined vulnerability patterns."""
        # Common vulnerability patterns
        predefined_patterns = [
            VulnerabilityPattern(
                pattern_id="buffer_overflow_001",
                pattern_type="buffer_overflow",
                signature=".*overflow.*|.*stack.*smash.*|.*heap.*overflow.*",
                confidence=0.8,
                description="Buffer overflow vulnerability pattern",
                affected_components=["memory", "stack", "heap"],
                indicators=["segfault", "corruption", "overflow"]
            ),
            VulnerabilityPattern(
                pattern_id="sql_injection_001",
                pattern_type="sql_injection",
                signature=".*union.*select.*|.*or.*1=1.*|.*drop.*table.*",
                confidence=0.9,
                description="SQL injection vulnerability pattern",
                affected_components=["database", "api", "auth"],
                indicators=["sql_error", "database_error", "injection"]
            ),
            VulnerabilityPattern(
                pattern_id="auth_bypass_001",
                pattern_type="auth_bypass",
                signature=".*admin.*true.*|.*auth.*bypass.*|.*session.*fixation.*",
                confidence=0.85,
                description="Authentication bypass vulnerability pattern",
                affected_components=["auth", "session", "login"],
                indicators=["unauthorized", "bypass", "privilege_escalation"]
            ),
            VulnerabilityPattern(
                pattern_id="xss_001",
                pattern_type="xss",
                signature=".*<script>.*|.*javascript:.*|.*onerror=.*",
                confidence=0.85,
                description="Cross-site scripting vulnerability pattern",
                affected_components=["web", "browser", "dom"],
                indicators=["script", "javascript", "xss"]
            ),
            VulnerabilityPattern(
                pattern_id="csrf_001",
                pattern_type="csrf",
                signature=".*csrf.*|.*cross.*site.*request.*",
                confidence=0.8,
                description="Cross-site request forgery pattern",
                affected_components=["web", "session", "form"],
                indicators=["csrf", "state_change", "unauthorized_request"]
            ),
            VulnerabilityPattern(
                pattern_id="rce_001",
                pattern_type="rce",
                signature=".*command.*execution.*|.*eval.*|.*system.*\\(.*",
                confidence=0.9,
                description="Remote code execution pattern",
                affected_components=["system", "shell", "exec"],
                indicators=["rce", "command_injection", "code_execution"]
            ),
            VulnerabilityPattern(
                pattern_id="ssrf_001",
                pattern_type="ssrf",
                signature=".*internal.*request.*|.*localhost.*|.*127\\.0\\.0\\.1.*",
                confidence=0.8,
                description="Server-side request forgery pattern",
                affected_components=["network", "http", "internal"],
                indicators=["internal_access", "ssrf", "port_scan"]
            ),
            VulnerabilityPattern(
                pattern_id="xxe_001",
                pattern_type="xxe",
                signature=".*<!DOCTYPE.*|.*ENTITY.*|.*SYSTEM.*",
                confidence=0.85,
                description="XML external entity injection pattern",
                affected_components=["xml", "parser", "file"],
                indicators=["xxe", "xml", "entity"]
            )
        ]
        
        self.pattern_database = predefined_patterns
        logger.info(f"Loaded {len(predefined_patterns)} predefined patterns")
    
    def add_pattern(self, pattern: VulnerabilityPattern):
        """
        Add a custom vulnerability pattern to the database.
        
        Args:
            pattern: The vulnerability pattern to add
        """
        self.pattern_database.append(pattern)
        logger.info(f"Added pattern: {pattern.pattern_id}")
    
    def extract_pattern_from_vulnerability(
        self,
        vulnerability_data: Dict[str, Any]
    ) -> Optional[VulnerabilityPattern]:
        """
        Extract a vulnerability pattern from discovered vulnerability data.
        
        Args:
            vulnerability_data: Raw vulnerability data from scanning
            
        Returns:
            Extracted vulnerability pattern if successful, None otherwise
        """
        try:
            # Determine pattern type from vulnerability data
            vuln_type = vulnerability_data.get('type', 'unknown')
            description = vulnerability_data.get('description', '')
            component = vulnerability_data.get('component', '')
            
            # Generate a signature based on key characteristics
            signature_parts = []
            
            if vuln_type:
                signature_parts.append(vuln_type.lower())
            if description:
                # Extract key terms from description
                words = re.findall(r'\b\w+\b', description.lower())
                signature_parts.extend(words[:5])  # Take first 5 words
            
            signature = '|'.join(signature_parts) if signature_parts else 'unknown'
            
            # Generate pattern ID
            pattern_hash = hashlib.md5(signature.encode()).hexdigest()[:8]
            pattern_id = f"{vuln_type}_{pattern_hash}"
            
            pattern = VulnerabilityPattern(
                pattern_id=pattern_id,
                pattern_type=vuln_type,
                signature=signature,
                confidence=vulnerability_data.get('confidence', 0.5),
                description=description,
                affected_components=[component] if component else [],
                indicators=vulnerability_data.get('indicators', []),
                protocol=vulnerability_data.get('protocol'),
                port=vulnerability_data.get('port'),
                metadata=vulnerability_data.get('metadata', {})
            )
            
            return pattern
            
        except Exception as e:
            logger.error(f"Error extracting pattern: {e}")
            return None
    
    def calculate_pattern_similarity(
        self,
        pattern1: VulnerabilityPattern,
        pattern2: VulnerabilityPattern
    ) -> float:
        """
        Calculate similarity between two vulnerability patterns.
        
        Args:
            pattern1: First pattern
            pattern2: Second pattern
            
        Returns:
            Similarity score between 0.0 and 1.0
        """
        score = 0.0
        
        # Pattern type match
        if pattern1.pattern_type == pattern2.pattern_type:
            score += 0.3
        
        # Signature similarity (regex match)
        try:
            if re.search(pattern1.signature, pattern2.signature, re.IGNORECASE):
                score += 0.4
        except re.error:
            pass
        
        # Component overlap
        component_overlap = set(pattern1.affected_components) & set(pattern2.affected_components)
        if component_overlap:
            score += 0.2 * (len(component_overlap) / max(len(pattern1.affected_components), 1))
        
        # Indicator overlap
        indicator_overlap = set(pattern1.indicators) & set(pattern2.indicators)
        if indicator_overlap:
            score += 0.1 * (len(indicator_overlap) / max(len(pattern1.indicators), 1))
        
        return min(score, 1.0)
    
    def calculate_description_similarity(self, description1: str, description2: str) -> float:
        """
        Calculate similarity between two descriptions using simple word overlap.
        
        Args:
            description1: First description
            description2: Second description
            
        Returns:
            Similarity score between 0.0 and 1.0
        """
        words1 = set(re.findall(r'\b\w+\b', description1.lower()))
        words2 = set(re.findall(r'\b\w+\b', description2.lower()))
        
        if not words1 or not words2:
            return 0.0
        
        intersection = words1 & words2
        union = words1 | words2
        
        return len(intersection) / len(union)
    
    async def match_pattern_against_cves(
        self,
        pattern: VulnerabilityPattern,
        search_keywords: Optional[List[str]] = None
    ) -> List[CVEMatch]:
        """
        Match a vulnerability pattern against known CVEs.
        
        Args:
            pattern: The vulnerability pattern to match
            search_keywords: Optional keywords to search for in CVE database
            
        Returns:
            List of CVE matches sorted by match score
        """
        matches = []
        
        # Determine search keywords
        if not search_keywords:
            search_keywords = []
            search_keywords.append(pattern.pattern_type)
            search_keywords.extend(pattern.affected_components)
            search_keywords.extend(pattern.indicators)
        
        # Search for CVEs using keywords
        all_cves = []
        for keyword in search_keywords[:3]:  # Limit to 3 keywords to avoid API overload
            try:
                async with self.nvd_db:
                    cves = await self.nvd_db.search_by_keyword(keyword)
                    all_cves.extend(cves)
            except Exception as e:
                logger.error(f"Error searching for CVEs with keyword '{keyword}': {e}")
        
        # Remove duplicates
        unique_cves = {cve.cve_id: cve for cve in all_cves}.values()
        
        # Score each CVE
        for cve in unique_cves:
            match_score = 0.0
            match_reasons = []
            
            # Signature similarity
            try:
                if re.search(pattern.signature, cve.description, re.IGNORECASE):
                    match_score += self.weights['signature_similarity']
                    match_reasons.append("Signature match in description")
            except re.error:
                pass
            
            # Description similarity
            desc_sim = self.calculate_description_similarity(
                pattern.description,
                cve.description
            )
            match_score += desc_sim * self.weights['description_similarity']
            if desc_sim > 0.3:
                match_reasons.append(f"Description similarity: {desc_sim:.2f}")
            
            # Component match
            for component in pattern.affected_components:
                if component.lower() in cve.description.lower():
                    match_score += self.weights['component_match']
                    match_reasons.append(f"Component match: {component}")
                    break
            
            # CVSS relevance (higher CVSS = more relevant for security)
            cvss_relevance = cve.cvss_score / 10.0
            match_score += cvss_relevance * self.weights['cvss_relevance']
            
            # Create match if score is above threshold
            if match_score > 0.3:
                match = CVEMatch(
                    pattern=pattern,
                    matched_cve=cve,
                    match_score=match_score,
                    match_reason='; '.join(match_reasons),
                    confidence=min(match_score * pattern.confidence, 1.0)
                )
                matches.append(match)
        
        # Sort by match score
        matches.sort(key=lambda m: m.match_score, reverse=True)
        
        # Store in history
        self.match_history.extend(matches)
        
        return matches
    
    async def match_vulnerability(
        self,
        vulnerability_data: Dict[str, Any]
    ) -> List[CVEMatch]:
        """
        Match a discovered vulnerability against known CVEs.
        
        Args:
            vulnerability_data: Raw vulnerability data from scanning
            
        Returns:
            List of CVE matches sorted by match score
        """
        # Extract pattern from vulnerability
        pattern = self.extract_pattern_from_vulnerability(vulnerability_data)
        if not pattern:
            logger.warning("Failed to extract pattern from vulnerability")
            return []
        
        # Match against CVEs
        matches = await self.match_pattern_against_cves(pattern)
        
        return matches
    
    async def batch_match_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, List[CVEMatch]]:
        """
        Match multiple vulnerabilities against known CVEs.
        
        Args:
            vulnerabilities: List of vulnerability data from scanning
            
        Returns:
            Dictionary mapping vulnerability identifiers to their CVE matches
        """
        results = {}
        
        for vuln in vulnerabilities:
            vuln_id = vuln.get('id', f"vuln_{hash(str(vuln))}")
            matches = await self.match_vulnerability(vuln)
            results[vuln_id] = matches
        
        return results
    
    def get_match_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about CVE matching history.
        
        Returns:
            Dictionary containing match statistics
        """
        if not self.match_history:
            return {
                'total_matches': 0,
                'unique_cves': 0,
                'avg_match_score': 0.0,
                'severity_distribution': {},
                'pattern_type_distribution': {}
            }
        
        total_matches = len(self.match_history)
        unique_cves = len(set(m.matched_cve.cve_id for m in self.match_history))
        avg_match_score = sum(m.match_score for m in self.match_history) / total_matches
        
        # Severity distribution
        severity_dist = {}
        for match in self.match_history:
            severity = match.matched_cve.severity.value
            severity_dist[severity] = severity_dist.get(severity, 0) + 1
        
        # Pattern type distribution
        pattern_type_dist = {}
        for match in self.match_history:
            pattern_type = match.pattern.pattern_type
            pattern_type_dist[pattern_type] = pattern_type_dist.get(pattern_type, 0) + 1
        
        return {
            'total_matches': total_matches,
            'unique_cves': unique_cves,
            'avg_match_score': avg_match_score,
            'severity_distribution': severity_dist,
            'pattern_type_distribution': pattern_type_dist
        }
    
    def export_matches_to_json(self, matches: List[CVEMatch]) -> str:
        """
        Export CVE matches to JSON format.
        
        Args:
            matches: List of CVE matches
            
        Returns:
            JSON string
        """
        export_data = []
        
        for match in matches:
            export_data.append({
                'pattern_id': match.pattern.pattern_id,
                'pattern_type': match.pattern.pattern_type,
                'cve_id': match.matched_cve.cve_id,
                'cve_description': match.matched_cve.description,
                'cvss_score': match.matched_cve.cvss_score,
                'severity': match.matched_cve.severity.value,
                'match_score': match.match_score,
                'match_reason': match.match_reason,
                'confidence': match.confidence,
                'timestamp': match.timestamp.isoformat()
            })
        
        return json.dumps(export_data, indent=2)
