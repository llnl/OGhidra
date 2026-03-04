"""
Lightweight Function Graph for Architectural Understanding

This module builds a call graph from function metadata to enable:
- Graph-aware RAG context expansion
- Domain-based clustering
- Architectural understanding queries

Author: OGhidra Enhanced Knowledge System
Date: 2026-02-19
"""

import logging
from typing import Dict, List, Set, Optional, Any, Tuple
from collections import defaultdict, deque

logger = logging.getLogger("ollama-ghidra-bridge.function_graph")


class FunctionNode:
    """Represents a function node in the call graph."""
    
    def __init__(self, address: str, name: str, metadata: Dict[str, Any]):
        self.address = address
        self.name = name
        self.metadata = metadata
        
        # Graph properties
        self.callers: Set[str] = set()  # Addresses of functions that call this
        self.callees: Set[str] = set()  # Addresses of functions this calls
        
        # Computed properties (cached)
        self._centrality: Optional[float] = None
        self._depth: Optional[int] = None
        self._cluster: Optional[str] = None
    
    @property
    def domain(self) -> str:
        """Get function's primary domain."""
        categories = self.metadata.get('categories', {})
        return categories.get('primary_domain', 'unknown')
    
    @property
    def security_level(self) -> str:
        """Get security criticality level."""
        security = self.metadata.get('security', {})
        return security.get('criticality', 'low')
    
    @property
    def operations(self) -> List[str]:
        """Get list of operations this function performs."""
        categories = self.metadata.get('categories', {})
        return categories.get('operations', [])
    
    def __repr__(self):
        return f"FunctionNode({self.name} @ {self.address})"


class FunctionGraph:
    """
    Lightweight function call graph for architectural understanding.
    
    Capabilities:
    - Build from function metadata
    - Find related functions (callers, callees, siblings)
    - Cluster by domain
    - Calculate centrality (importance)
    - Expand context for RAG queries
    """
    
    def __init__(self):
        self.nodes: Dict[str, FunctionNode] = {}  # address -> node
        self.clusters: Dict[str, List[str]] = defaultdict(list)  # domain -> [addresses]
        self._centrality_cache: Dict[str, float] = {}
        
        self.logger = logger
    
    def add_function(self, address: str, name: str, metadata: Dict[str, Any]) -> None:
        """
        Add a function to the graph.
        
        Args:
            address: Function address
            name: Function name
            metadata: Complete function metadata dict
        """
        if address in self.nodes:
            # Update existing node
            node = self.nodes[address]
            node.name = name
            node.metadata = metadata
        else:
            # Create new node
            node = FunctionNode(address, name, metadata)
            self.nodes[address] = node
        
        # Extract dependencies and add edges
        dependencies = metadata.get('dependencies', {})
        
        # Add callee edges
        for callee in dependencies.get('calls', []):
            callee_addr = callee.get('address', '')
            if callee_addr and callee_addr != 'unknown':
                node.callees.add(callee_addr)
                # Create stub node for callee if doesn't exist
                if callee_addr not in self.nodes:
                    self.nodes[callee_addr] = FunctionNode(callee_addr, f"FUN_{callee_addr[:8]}", {})
                # Add reverse edge
                self.nodes[callee_addr].callers.add(address)
        
        # Add caller edges
        for caller in dependencies.get('called_by', []):
            caller_addr = caller.get('address', '')
            if caller_addr and caller_addr != 'unknown':
                node.callers.add(caller_addr)
                # Create stub node for caller if doesn't exist
                if caller_addr not in self.nodes:
                    self.nodes[caller_addr] = FunctionNode(caller_addr, f"FUN_{caller_addr[:8]}", {})
                # Add forward edge
                self.nodes[caller_addr].callees.add(address)
        
        # Add to domain cluster
        domain = node.domain
        if domain and address not in self.clusters[domain]:
            self.clusters[domain].append(address)
        
        # Invalidate centrality cache
        self._centrality_cache.clear()
    
    def get_node(self, address: str) -> Optional[FunctionNode]:
        """Get a function node by address."""
        return self.nodes.get(address)
    
    def get_related_functions(self, address: str, 
                             depth: int = 1,
                             include_callers: bool = True,
                             include_callees: bool = True) -> List[str]:
        """
        Get functions related to the given function.
        
        Args:
            address: Starting function address
            depth: How many hops to traverse (1 = immediate, 2 = 2 hops, etc.)
            include_callers: Include functions that call this one
            include_callees: Include functions this one calls
        
        Returns:
            List of related function addresses
        """
        if address not in self.nodes:
            return []
        
        related = set()
        visited = set()
        queue = deque([(address, 0)])  # (address, current_depth)
        
        while queue:
            current_addr, current_depth = queue.popleft()
            
            if current_addr in visited or current_depth > depth:
                continue
            
            visited.add(current_addr)
            
            if current_addr != address:  # Don't include the starting node
                related.add(current_addr)
            
            if current_depth < depth:
                node = self.nodes.get(current_addr)
                if node:
                    # Add callers
                    if include_callers:
                        for caller in node.callers:
                            if caller not in visited:
                                queue.append((caller, current_depth + 1))
                    
                    # Add callees
                    if include_callees:
                        for callee in node.callees:
                            if callee not in visited:
                                queue.append((callee, current_depth + 1))
        
        return list(related)
    
    def get_domain_functions(self, domain: str, limit: int = 20) -> List[str]:
        """
        Get functions in a specific domain.
        
        Args:
            domain: Domain name (e.g., 'authentication', 'cryptography', 'networking')
            limit: Maximum functions to return
        
        Returns:
            List of function addresses in that domain
        """
        return self.clusters.get(domain, [])[:limit]
    
    def get_all_domains(self) -> List[Tuple[str, int]]:
        """
        Get all domains with their function counts.
        
        Returns:
            List of (domain_name, function_count) tuples, sorted by count
        """
        domains = [(domain, len(addrs)) for domain, addrs in self.clusters.items()]
        return sorted(domains, key=lambda x: x[1], reverse=True)
    
    def calculate_centrality(self, address: str) -> float:
        """
        Calculate importance/centrality of a function.
        
        Uses degree centrality: (in_degree + out_degree) / (2 * (n - 1))
        Higher score = more connected = more important
        
        Args:
            address: Function address
        
        Returns:
            Centrality score (0.0 to 1.0)
        """
        if address in self._centrality_cache:
            return self._centrality_cache[address]
        
        node = self.nodes.get(address)
        if not node:
            return 0.0
        
        # Degree centrality
        in_degree = len(node.callers)
        out_degree = len(node.callees)
        total_degree = in_degree + out_degree
        
        # Normalize
        n = len(self.nodes)
        if n <= 1:
            centrality = 0.0
        else:
            max_possible = 2 * (n - 1)
            centrality = total_degree / max_possible
        
        self._centrality_cache[address] = centrality
        return centrality
    
    def get_high_centrality_functions(self, top_k: int = 10) -> List[Tuple[str, float]]:
        """
        Get functions with highest centrality (most important/connected).
        
        Args:
            top_k: Number of functions to return
        
        Returns:
            List of (address, centrality_score) tuples
        """
        centralities = [(addr, self.calculate_centrality(addr)) for addr in self.nodes.keys()]
        centralities.sort(key=lambda x: x[1], reverse=True)
        return centralities[:top_k]
    
    def expand_context_for_rag(self, 
                               primary_results: List[str],
                               expansion_depth: int = 1,
                               max_expanded: int = 10) -> List[str]:
        """
        Expand RAG search results with graph neighbors for better context.
        
        This is the key method for enhancing RAG with graph information.
        
        Args:
            primary_results: Addresses from semantic/vector search
            expansion_depth: How many hops to expand (1 = immediate neighbors)
            max_expanded: Maximum total functions to return
        
        Returns:
            Expanded list of function addresses (includes originals + neighbors)
        """
        expanded = set(primary_results)
        
        # For each primary result, add its important neighbors
        for address in primary_results:
            if len(expanded) >= max_expanded:
                break
            
            # Get immediate callers and callees
            related = self.get_related_functions(
                address, 
                depth=expansion_depth,
                include_callers=True,
                include_callees=True
            )
            
            # Sort by centrality (add most important first)
            related_with_centrality = [(addr, self.calculate_centrality(addr)) for addr in related]
            related_with_centrality.sort(key=lambda x: x[1], reverse=True)
            
            # Add top neighbors
            for neighbor_addr, _ in related_with_centrality:
                if len(expanded) >= max_expanded:
                    break
                expanded.add(neighbor_addr)
        
        return list(expanded)
    
    def find_execution_paths(self, 
                            from_address: str,
                            to_address: str,
                            max_depth: int = 5,
                            max_paths: int = 5) -> List[List[str]]:
        """
        Find execution paths between two functions.
        
        Args:
            from_address: Starting function
            to_address: Target function
            max_depth: Maximum path length
            max_paths: Maximum number of paths to return
        
        Returns:
            List of paths, where each path is a list of addresses
        """
        paths = []
        
        def dfs(current: str, target: str, path: List[str], depth: int):
            if len(paths) >= max_paths or depth > max_depth:
                return
            
            if current == target:
                paths.append(path[:])
                return
            
            node = self.nodes.get(current)
            if not node:
                return
            
            # Explore callees
            for callee in node.callees:
                if callee not in path:  # Avoid cycles
                    path.append(callee)
                    dfs(callee, target, path, depth + 1)
                    path.pop()
        
        if from_address in self.nodes:
            dfs(from_address, to_address, [from_address], 0)
        
        return paths
    
    def get_entry_points(self, top_k: int = 10) -> List[str]:
        """
        Find likely entry point functions (high out-degree, low in-degree).
        
        Args:
            top_k: Number of entry points to return
        
        Returns:
            List of function addresses
        """
        entry_points = []
        
        for address, node in self.nodes.items():
            in_degree = len(node.callers)
            out_degree = len(node.callees)
            
            # Entry points: called by few, call many
            if out_degree > 2 and (in_degree == 0 or out_degree / (in_degree + 1) > 2):
                score = out_degree - in_degree
                entry_points.append((address, score))
        
        entry_points.sort(key=lambda x: x[1], reverse=True)
        return [addr for addr, _ in entry_points[:top_k]]
    
    def get_leaf_functions(self, top_k: int = 10) -> List[str]:
        """
        Find leaf functions (called by many, call few/none).
        
        Args:
            top_k: Number of leaf functions to return
        
        Returns:
            List of function addresses
        """
        leaves = []
        
        for address, node in self.nodes.items():
            in_degree = len(node.callers)
            out_degree = len(node.callees)
            
            # Leaf functions: called by many, call few
            if in_degree > 2 and (out_degree == 0 or in_degree / (out_degree + 1) > 2):
                score = in_degree - out_degree
                leaves.append((address, score))
        
        leaves.sort(key=lambda x: x[1], reverse=True)
        return [addr for addr, _ in leaves[:top_k]]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get graph statistics."""
        total_nodes = len(self.nodes)
        total_edges = sum(len(node.callees) for node in self.nodes.values())
        
        # Calculate average degree
        avg_degree = (2 * total_edges) / total_nodes if total_nodes > 0 else 0
        
        # Find isolated nodes
        isolated = sum(1 for node in self.nodes.values() 
                      if len(node.callers) == 0 and len(node.callees) == 0)
        
        return {
            'total_functions': total_nodes,
            'total_edges': total_edges,
            'avg_degree': avg_degree,
            'isolated_functions': isolated,
            'domains': len(self.clusters),
            'largest_domain': max(self.clusters.items(), key=lambda x: len(x[1]))[0] if self.clusters else None,
        }
    
    def __len__(self):
        return len(self.nodes)
    
    def __contains__(self, address: str):
        return address in self.nodes
