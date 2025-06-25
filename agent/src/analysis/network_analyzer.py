"""
Network Analysis for Solana
Maps relationships between addresses and identifies clusters
"""

import asyncio
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque
import networkx as nx

class NetworkAnalyzer:
    """
    Analyze address relationships and network patterns
    """
    
    def __init__(self):
        self.network_patterns = {
            'cluster_indicators': {
                'common_patterns': [
                    'shared_timing', 'similar_amounts', 'sequential_transactions',
                    'common_programs', 'funding_source', 'interaction_frequency'
                ],
                'suspicious_patterns': [
                    'wash_trading', 'circular_transactions', 'coordinated_activity',
                    'bot_networks', 'sybil_attacks', 'money_laundering'
                ]
            },
            'relationship_types': {
                'direct': ['sender_to_receiver', 'program_interaction'],
                'indirect': ['common_counterparty', 'shared_program', 'timing_correlation'],
                'financial': ['funding_relationship', 'liquidity_provision', 'arbitrage']
            },
            'risk_propagation': {
                'high_risk_spread': 3,      # Degrees of separation for high-risk spread
                'medium_risk_spread': 2,    # Degrees for medium-risk spread
                'risk_decay_factor': 0.5    # How much risk decays per degree
            }
        }
        
        # In-memory network graph
        self.address_network = nx.DiGraph()
        self.risk_scores = {}
        self.address_metadata = {}
    
    async def analyze_address_network(self, target_address: str, transaction_data: Dict) -> Dict:
        """
        Analyze network relationships for a target address
        """
        network_analysis = {
            'target_address': target_address,
            'network_risk_score': 0.0,
            'relationship_analysis': {},
            'cluster_analysis': {},
            'risk_propagation': {},
            'suspicious_patterns': [],
            'network_recommendations': []
        }
        
        try:
            # 1. Build/update network graph
            await self._update_network_graph(target_address, transaction_data)
            
            # 2. Analyze direct relationships
            network_analysis['relationship_analysis'] = await self._analyze_direct_relationships(target_address)
            
            # 3. Perform cluster analysis
            network_analysis['cluster_analysis'] = await self._perform_cluster_analysis(target_address)
            
            # 4. Analyze risk propagation
            network_analysis['risk_propagation'] = await self._analyze_risk_propagation(target_address)
            
            # 5. Detect suspicious patterns
            network_analysis['suspicious_patterns'] = await self._detect_suspicious_network_patterns(target_address)
            
            # 6. Calculate network risk score
            network_analysis['network_risk_score'] = await self._calculate_network_risk_score(
                network_analysis['relationship_analysis'],
                network_analysis['cluster_analysis'],
                network_analysis['risk_propagation'],
                network_analysis['suspicious_patterns']
            )
            
            # 7. Generate recommendations
            network_analysis['network_recommendations'] = await self._generate_network_recommendations(
                network_analysis
            )
        
        except Exception as e:
            network_analysis['error'] = f"Network analysis failed: {str(e)}"
        
        return network_analysis
    
    async def _update_network_graph(self, target_address: str, transaction_data: Dict):
        """Update the network graph with new transaction data"""
        
        # Extract addresses from transaction
        from_address = transaction_data.get('from_address')
        to_address = transaction_data.get('to_address')
        program_id = transaction_data.get('program_id')
        
        # Add nodes if they don't exist
        for address in [from_address, to_address, program_id]:
            if address and address not in self.address_network:
                self.address_network.add_node(address)
                self.address_metadata[address] = {
                    'first_seen': transaction_data.get('timestamp'),
                    'transaction_count': 0,
                    'total_volume': 0.0,
                    'programs_used': set(),
                    'counterparties': set()
                }
        
        # Update metadata
        if from_address:
            metadata = self.address_metadata.get(from_address, {})
            metadata['transaction_count'] = metadata.get('transaction_count', 0) + 1
            metadata['total_volume'] = metadata.get('total_volume', 0) + float(transaction_data.get('value', 0))
            if program_id:
                metadata.setdefault('programs_used', set()).add(program_id)
            if to_address:
                metadata.setdefault('counterparties', set()).add(to_address)
        
        # Add edges
        if from_address and to_address:
            if self.address_network.has_edge(from_address, to_address):
                # Update existing edge
                edge_data = self.address_network[from_address][to_address]
                edge_data['weight'] = edge_data.get('weight', 0) + 1
                edge_data['total_amount'] = edge_data.get('total_amount', 0) + float(transaction_data.get('value', 0))
                edge_data['last_transaction'] = transaction_data.get('timestamp')
            else:
                # Add new edge
                self.address_network.add_edge(from_address, to_address, 
                                            weight=1,
                                            total_amount=float(transaction_data.get('value', 0)),
                                            first_transaction=transaction_data.get('timestamp'),
                                            last_transaction=transaction_data.get('timestamp'),
                                            program_id=program_id)
    
    async def _analyze_direct_relationships(self, target_address: str) -> Dict:
        """Analyze direct relationships of the target address"""
        relationship_analysis = {
            'incoming_relationships': [],
            'outgoing_relationships': [],
            'relationship_strength': {},
            'suspicious_relationships': []
        }
        
        if target_address not in self.address_network:
            return relationship_analysis
        
        # Analyze incoming relationships
        for predecessor in self.address_network.predecessors(target_address):
            edge_data = self.address_network[predecessor][target_address]
            relationship_strength = await self._calculate_relationship_strength(edge_data)
            
            relationship_analysis['incoming_relationships'].append({
                'address': predecessor,
                'strength': relationship_strength,
                'transaction_count': edge_data.get('weight', 0),
                'total_amount': edge_data.get('total_amount', 0),
                'risk_score': self.risk_scores.get(predecessor, 0.0)
            })
        
        # Analyze outgoing relationships
        for successor in self.address_network.successors(target_address):
            edge_data = self.address_network[target_address][successor]
            relationship_strength = await self._calculate_relationship_strength(edge_data)
            
            relationship_analysis['outgoing_relationships'].append({
                'address': successor,
                'strength': relationship_strength,
                'transaction_count': edge_data.get('weight', 0),
                'total_amount': edge_data.get('total_amount', 0),
                'risk_score': self.risk_scores.get(successor, 0.0)
            })
        
        # Identify suspicious relationships
        all_relationships = (relationship_analysis['incoming_relationships'] + 
                           relationship_analysis['outgoing_relationships'])
        
        for relationship in all_relationships:
            if (relationship['risk_score'] > 0.7 or 
                relationship['strength'] > 0.8 or
                relationship['transaction_count'] > 100):
                relationship_analysis['suspicious_relationships'].append(relationship)
        
        return relationship_analysis
    
    async def _perform_cluster_analysis(self, target_address: str) -> Dict:
        """Perform cluster analysis to identify related addresses"""
        cluster_analysis = {
            'cluster_id': None,
            'cluster_size': 0,
            'cluster_members': [],
            'cluster_risk_score': 0.0,
            'cluster_characteristics': {}
        }
        
        if target_address not in self.address_network:
            return cluster_analysis
        
        # Find strongly connected components
        try:
            # Convert to undirected for community detection
            undirected_graph = self.address_network.to_undirected()
            
            # Simple clustering based on connected components
            if target_address in undirected_graph:
                # Get connected component containing target address
                cluster_members = list(nx.node_connected_component(undirected_graph, target_address))
                
                cluster_analysis['cluster_members'] = cluster_members
                cluster_analysis['cluster_size'] = len(cluster_members)
                
                # Calculate cluster characteristics
                cluster_analysis['cluster_characteristics'] = await self._analyze_cluster_characteristics(
                    cluster_members
                )
                
                # Calculate cluster risk score
                cluster_risks = [self.risk_scores.get(addr, 0.0) for addr in cluster_members]
                if cluster_risks:
                    cluster_analysis['cluster_risk_score'] = max(cluster_risks)
                
                # Generate cluster ID (hash of sorted members)
                cluster_id = hashlib.md5(''.join(sorted(cluster_members)).encode()).hexdigest()[:8]
                cluster_analysis['cluster_id'] = cluster_id
        
        except Exception as e:
            cluster_analysis['error'] = f"Cluster analysis failed: {str(e)}"
        
        return cluster_analysis
    
    async def _analyze_risk_propagation(self, target_address: str) -> Dict:
        """Analyze how risk propagates through the network"""
        risk_propagation = {
            'inherited_risk': 0.0,
            'risk_sources': [],
            'risk_path_analysis': {},
            'contamination_level': 'none'
        }
        
        if target_address not in self.address_network:
            return risk_propagation
        
        try:
            # Find risky addresses within specified degrees
            max_degrees = self.network_patterns['risk_propagation']['high_risk_spread']
            decay_factor = self.network_patterns['risk_propagation']['risk_decay_factor']
            
            # BFS to find risk sources
            visited = set()
            queue = deque([(target_address, 0, 1.0)])  # (address, degree, risk_multiplier)
            
            while queue:
                current_addr, degree, risk_multiplier = queue.popleft()
                
                if current_addr in visited or degree > max_degrees:
                    continue
                
                visited.add(current_addr)
                current_risk = self.risk_scores.get(current_addr, 0.0)
                
                if current_risk > 0.5 and current_addr != target_address:
                    inherited_risk = current_risk * risk_multiplier
                    risk_propagation['risk_sources'].append({
                        'address': current_addr,
                        'risk_score': current_risk,
                        'inherited_risk': inherited_risk,
                        'degrees_away': degree,
                        'path_strength': risk_multiplier
                    })
                    risk_propagation['inherited_risk'] = max(
                        risk_propagation['inherited_risk'], inherited_risk
                    )
                
                # Add neighbors to queue
                next_risk_multiplier = risk_multiplier * decay_factor
                for neighbor in self.address_network.neighbors(current_addr):
                    if neighbor not in visited:
                        queue.append((neighbor, degree + 1, next_risk_multiplier))
            
            # Determine contamination level
            if risk_propagation['inherited_risk'] > 0.8:
                risk_propagation['contamination_level'] = 'high'
            elif risk_propagation['inherited_risk'] > 0.5:
                risk_propagation['contamination_level'] = 'medium'
            elif risk_propagation['inherited_risk'] > 0.2:
                risk_propagation['contamination_level'] = 'low'
        
        except Exception as e:
            risk_propagation['error'] = f"Risk propagation analysis failed: {str(e)}"
        
        return risk_propagation
    
    async def _detect_suspicious_network_patterns(self, target_address: str) -> List[Dict]:
        """Detect suspicious patterns in the network"""
        suspicious_patterns = []
        
        if target_address not in self.address_network:
            return suspicious_patterns
        
        try:
            # Pattern 1: Circular transaction patterns
            circular_patterns = await self._detect_circular_patterns(target_address)
            suspicious_patterns.extend(circular_patterns)
            
            # Pattern 2: Bot-like behavior
            bot_patterns = await self._detect_bot_patterns(target_address)
            suspicious_patterns.extend(bot_patterns)
            
            # Pattern 3: Wash trading patterns
            wash_trading_patterns = await self._detect_wash_trading(target_address)
            suspicious_patterns.extend(wash_trading_patterns)
            
            # Pattern 4: Coordinated activity
            coordinated_patterns = await self._detect_coordinated_activity(target_address)
            suspicious_patterns.extend(coordinated_patterns)
        
        except Exception as e:
            suspicious_patterns.append({
                'pattern_type': 'analysis_error',
                'description': f"Pattern detection failed: {str(e)}",
                'risk_score': 0.5
            })
        
        return suspicious_patterns
    
    async def _calculate_network_risk_score(self, relationship_analysis: Dict, cluster_analysis: Dict,
                                          risk_propagation: Dict, suspicious_patterns: List[Dict]) -> float:
        """Calculate overall network risk score"""
        
        risk_factors = []
        
        # Relationship risk
        suspicious_relationships = relationship_analysis.get('suspicious_relationships', [])
        if suspicious_relationships:
            max_relationship_risk = max(rel['risk_score'] for rel in suspicious_relationships)
            risk_factors.append(max_relationship_risk * 0.3)
        
        # Cluster risk
        cluster_risk = cluster_analysis.get('cluster_risk_score', 0.0)
        risk_factors.append(cluster_risk * 0.2)
        
        # Risk propagation
        inherited_risk = risk_propagation.get('inherited_risk', 0.0)
        risk_factors.append(inherited_risk * 0.3)
        
        # Suspicious patterns
        if suspicious_patterns:
            max_pattern_risk = max(pattern.get('risk_score', 0) for pattern in suspicious_patterns)
            risk_factors.append(max_pattern_risk * 0.2)
        
        return min(sum(risk_factors), 1.0)
    
    # Helper methods (would be implemented with real network analysis algorithms)
    async def _calculate_relationship_strength(self, edge_data: Dict) -> float:
        """Calculate strength of relationship based on edge data"""
        transaction_count = edge_data.get('weight', 0)
        total_amount = edge_data.get('total_amount', 0)
        
        # Simple strength calculation
        strength = min((transaction_count / 10.0) + (total_amount / 1000.0), 1.0)
        return strength
    
    async def _analyze_cluster_characteristics(self, cluster_members: List[str]) -> Dict:
        """Analyze characteristics of a cluster"""
        return {
            'avg_transaction_count': 0.0,
            'total_volume': 0.0,
            'common_programs': [],
            'temporal_clustering': False
        }  # Placeholder
    
    async def _detect_circular_patterns(self, target_address: str) -> List[Dict]:
        """Detect circular transaction patterns"""
        return []  # Placeholder
    
    async def _detect_bot_patterns(self, target_address: str) -> List[Dict]:
        """Detect bot-like behavior patterns"""
        return []  # Placeholder
    
    async def _detect_wash_trading(self, target_address: str) -> List[Dict]:
        """Detect wash trading patterns"""
        return []  # Placeholder
    
    async def _detect_coordinated_activity(self, target_address: str) -> List[Dict]:
        """Detect coordinated activity patterns"""
        return []  # Placeholder
    
    async def _generate_network_recommendations(self, network_analysis: Dict) -> List[str]:
        """Generate network-based recommendations"""
        recommendations = []
        
        risk_score = network_analysis.get('network_risk_score', 0.0)
        
        if risk_score > 0.8:
            recommendations.append("🚨 High network risk - address is connected to multiple high-risk entities")
        elif risk_score > 0.6:
            recommendations.append("⚠️ Moderate network risk - exercise increased caution")
        
        suspicious_patterns = network_analysis.get('suspicious_patterns', [])
        if suspicious_patterns:
            recommendations.append(f"🔍 {len(suspicious_patterns)} suspicious network patterns detected")
        
        contamination = network_analysis.get('risk_propagation', {}).get('contamination_level', 'none')
        if contamination in ['high', 'medium']:
            recommendations.append(f"☣️ {contamination.title()} risk contamination from connected addresses")
        
        if not recommendations:
            recommendations.append("✅ Network analysis shows standard activity patterns")
        
        return recommendations