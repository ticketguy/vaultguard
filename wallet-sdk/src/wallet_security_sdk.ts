/**
 * Wallet Security SDK for Browser Wallets (TypeScript)
 * Simple decision service - wallets handle hiding/showing with existing mechanisms
 */

// ========== TYPE DEFINITIONS ==========

export interface SecurityConfig {
    agent_url?: string;
    api_key?: string;
    timeout?: number;
  }
  
  export interface TransactionData {
    hash?: string;
    from_address?: string;
    to_address?: string;
    amount?: string | number;
    value?: string | number;
    value_usd?: number;
    token_address?: string;
    token_name?: string;
    program_id?: string;
    instruction_data?: any;
    transaction_type?: string;
    dapp_url?: string;
    dapp_name?: string;
    user_id?: string;
    user_language?: string;
    additional_data?: Record<string, any>;
  }
  
  export interface SecurityDecision {
    action: 'allow' | 'hide' | 'warn' | 'block';
    risk_score: number;
    confidence: number;
    reasoning: string;
    user_explanation: string;
    threat_categories: string[];
    chain_of_thought: string[];
    technical_details?: Record<string, any>;
    analysis_time_ms?: number;
  }
  
  export interface SecurityAnalysisResult {
    quarantine_recommended: boolean;
    risk_score: number;
    confidence: number;
    reasoning: string;
    user_explanation: string;
    threat_categories: string[];
    chain_of_thought: string[];
    technical_details: Record<string, any>;
    analysis_time_ms: number;
    ai_generated_code?: string;
    action: 'ALLOW' | 'WARN' | 'BLOCK';
    analysis_method?: string;
  }
  
  export type SecurityCallback = (data: any) => void | Promise<void>;
  
  // ========== MAIN SDK CLASS ==========
  
  export class WalletSecuritySDK {
    private walletProviderId: string;
    private config: SecurityConfig;
    private agentUrl: string;
    private callbacks: Record<string, SecurityCallback>;
  
    constructor(walletProviderId: string, config: SecurityConfig = {}) {
      this.walletProviderId = walletProviderId;
      this.config = config;
      this.agentUrl = config.agent_url || 'http://localhost:8001';
      
      this.callbacks = {
        on_threat_detected: null,
        on_analysis_complete: null
      };
    }
  
    async initialize(): Promise<void> {
      console.log(`🔌 Initializing Wallet Security SDK for ${this.walletProviderId}`);
      
      // Test connection to security agent
      await this.connectToSecurityAgent();
      
      console.log('✅ Wallet Security SDK initialized');
    }
  
    private async connectToSecurityAgent(): Promise<boolean> {
      try {
        const response = await fetch(`${this.agentUrl}/health`, {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json'
          }
        });
        
        if (response.ok) {
          console.log(`🤖 Connected to AI Security Agent at ${this.agentUrl}`);
          return true;
        } else {
          console.warn(`⚠️ Security agent responded with status ${response.status}`);
          return false;
        }
      } catch (error) {
        console.error(`❌ Failed to connect to security agent: ${error}`);
        console.log('🔄 Will attempt to connect on first transaction');
        return false;
      }
    }
  
    // ========== CORE API FOR WALLET PROVIDERS ==========
  
    async analyzeIncomingTransaction(transactionData: TransactionData): Promise<SecurityDecision> {
      console.log(`🔍 Analyzing incoming transaction: ${transactionData.hash || 'unknown'}`);
      
      const enhancedData: TransactionData = {
        ...transactionData,
        transaction_type: 'incoming',
        additional_data: {
          ...transactionData.additional_data,
          analysis_type: 'incoming_transaction',
          wallet_provider: this.walletProviderId
        }
      };
      
      const analysisResult = await this.analyzeWithAiAgent(enhancedData);
      
      // Convert to simple decision for wallet
      return this.convertToWalletDecision(analysisResult, 'incoming');
    }
  
    async analyzeOutgoingTransaction(transactionData: TransactionData): Promise<SecurityDecision> {
      console.log(`🚀 Analyzing outgoing transaction to: ${transactionData.to_address || 'unknown'}`);
      
      const enhancedData: TransactionData = {
        ...transactionData,
        transaction_type: 'outgoing', 
        additional_data: {
          ...transactionData.additional_data,
          analysis_type: 'outgoing_transaction',
          wallet_provider: this.walletProviderId
        }
      };
      
      const analysisResult = await this.analyzeWithAiAgent(enhancedData);
      
      // Convert to simple decision for wallet
      return this.convertToWalletDecision(analysisResult, 'outgoing');
    }
  
    async analyzeToken(tokenData: TransactionData): Promise<SecurityDecision> {
      console.log(`🪙 Analyzing token: ${tokenData.token_name || 'unknown'}`);
      
      const enhancedData: TransactionData = {
        ...tokenData,
        transaction_type: 'token_analysis',
        additional_data: {
          ...tokenData.additional_data,
          analysis_type: 'token_analysis',
          wallet_provider: this.walletProviderId
        }
      };
      
      const analysisResult = await this.analyzeWithAiAgent(enhancedData);
      
      return this.convertToWalletDecision(analysisResult, 'token');
    }
  
    async analyzeDApp(dappUrl: string, dappName?: string): Promise<SecurityDecision> {
      console.log(`🌐 Analyzing DApp: ${dappName || dappUrl}`);
      
      const dappData: TransactionData = {
        dapp_url: dappUrl,
        dapp_name: dappName,
        transaction_type: 'dapp_analysis',
        additional_data: {
          analysis_type: 'dapp_analysis',
          wallet_provider: this.walletProviderId
        }
      };
      
      const analysisResult = await this.analyzeWithAiAgent(dappData);
      
      return this.convertToWalletDecision(analysisResult, 'dapp');
    }
  
    // ========== DECISION CONVERSION ==========
  
    private convertToWalletDecision(analysisResult: SecurityAnalysisResult, type: string): SecurityDecision {
      const { risk_score, confidence, threat_categories } = analysisResult;
      
      let action: 'allow' | 'hide' | 'warn' | 'block';
      
      if (type === 'incoming') {
        // For incoming transactions/tokens - hide risky items
        if (risk_score > 0.7) {
          action = 'hide';
        } else if (risk_score > 0.4) {
          action = 'warn'; // Wallet can choose to show with warning
        } else {
          action = 'allow';
        }
      } else if (type === 'outgoing') {
        // For outgoing transactions - block dangerous ones
        if (risk_score > 0.8 && confidence > 0.7) {
          action = 'block';
        } else if (risk_score > 0.4) {
          action = 'warn';
        } else {
          action = 'allow';
        }
      } else {
        // General analysis
        if (risk_score > 0.8) {
          action = 'hide';
        } else if (risk_score > 0.5) {
          action = 'warn';
        } else {
          action = 'allow';
        }
      }
      
      // Notify callback if threat detected
      if (action !== 'allow' && this.callbacks.on_threat_detected) {
        this.callbacks.on_threat_detected({
          action,
          risk_score,
          threat_categories,
          reasoning: analysisResult.reasoning
        });
      }
      
      return {
        action,
        risk_score,
        confidence,
        reasoning: analysisResult.reasoning,
        user_explanation: analysisResult.user_explanation,
        threat_categories,
        chain_of_thought: analysisResult.chain_of_thought,
        technical_details: analysisResult.technical_details,
        analysis_time_ms: analysisResult.analysis_time_ms
      };
    }
  
    // ========== REAL AI AGENT CONNECTION ==========
  
    private async analyzeWithAiAgent(transactionData: TransactionData): Promise<SecurityAnalysisResult> {
      try {
        const payload = {
          transaction_hash: transactionData.hash,
          from_address: transactionData.from_address,
          to_address: transactionData.to_address,
          amount: transactionData.amount || transactionData.value,
          value_usd: transactionData.value_usd,
          token_address: transactionData.token_address,
          token_name: transactionData.token_name,
          program_id: transactionData.program_id,
          instruction_data: transactionData.instruction_data,
          transaction_type: transactionData.transaction_type || 'transfer',
          dapp_url: transactionData.dapp_url,
          dapp_name: transactionData.dapp_name,
          user_id: transactionData.user_id,
          wallet_provider: this.walletProviderId,
          user_language: transactionData.user_language || 'english',
          additional_data: transactionData.additional_data || {}
        };
        
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
          'X-Wallet-Provider': this.walletProviderId
        };
        
        if (this.config.api_key) {
          headers['X-API-Key'] = this.config.api_key;
        }
        
        console.log(`🤖 Sending to AI agent: ${this.agentUrl}/api/v1/analyze-transaction`);
        
        const response = await fetch(`${this.agentUrl}/api/v1/analyze-transaction`, {
          method: 'POST',
          headers,
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(this.config.timeout || 30000)
        });
        
        if (response.ok) {
          const result = await response.json();
          console.log(`✅ AI analysis complete - Risk: ${result.risk_score?.toFixed(2) || 0}`);
          
          // Notify analysis complete callback
          if (this.callbacks.on_analysis_complete) {
            this.callbacks.on_analysis_complete(result);
          }
          
          return {
            quarantine_recommended: ['WARN', 'BLOCK'].includes(result.action),
            risk_score: result.risk_score || 0,
            confidence: result.confidence || 0,
            reasoning: result.user_explanation || '',
            user_explanation: result.user_explanation || '',
            threat_categories: result.threat_categories || [],
            chain_of_thought: result.chain_of_thought || [],
            technical_details: result.technical_details || {},
            analysis_time_ms: result.analysis_time_ms || 0,
            ai_generated_code: result.ai_generated_code || '',
            action: result.action || 'ALLOW'
          };
        } else {
          const errorText = await response.text();
          console.error(`❌ API error ${response.status}: ${errorText}`);
          return this.fallbackAnalysis(transactionData, `API error: ${response.status}`);
        }
      } catch (error) {
        if (error.name === 'TimeoutError') {
          console.error('⏰ AI analysis timeout');
          return this.fallbackAnalysis(transactionData, 'Analysis timeout');
        } else {
          console.error(`💥 AI analysis failed: ${error}`);
          return this.fallbackAnalysis(transactionData, `Analysis failed: ${error}`);
        }
      }
    }
  
    private fallbackAnalysis(transactionData: TransactionData, errorReason: string): SecurityAnalysisResult {
      console.warn(`🔄 Using fallback analysis: ${errorReason}`);
      
      let riskScore = 0.0;
      const threats: string[] = [];
      
      // Basic rule-based analysis as fallback
      const fromAddress = String(transactionData.from_address || '').toLowerCase();
      const tokenName = String(transactionData.token_name || '').toLowerCase();
      const value = Number(transactionData.amount || transactionData.value || 0);
      
      // Known scammer patterns
      if (['dead', '1111', '0000'].some(pattern => fromAddress.includes(pattern))) {
        riskScore += 0.8;
        threats.push('suspicious_address_pattern');
      }
      
      // Fake token patterns
      if (['fake', 'scam', 'test'].some(fake => tokenName.includes(fake))) {
        riskScore += 0.9;
        threats.push('fake_token');
      }
      
      // Dust attacks
      if (value > 0 && value < 0.001) {
        riskScore += 0.6;
        threats.push('dust_attack');
      }
      
      return {
        quarantine_recommended: riskScore > 0.5,
        risk_score: Math.min(riskScore, 1.0),
        confidence: 0.3,
        reasoning: `Fallback analysis: ${errorReason}. Risk score: ${riskScore.toFixed(2)}`,
        user_explanation: `Fallback analysis: ${errorReason}`,
        threat_categories: threats,
        chain_of_thought: [
          `AI agent unavailable: ${errorReason}`,
          'Using basic rule-based fallback analysis',
          `Detected threats: ${threats.join(', ')}`,
          `Final risk score: ${Math.min(riskScore, 1.0).toFixed(2)}`
        ],
        technical_details: { fallback: true, error: errorReason },
        analysis_time_ms: 0,
        action: riskScore > 0.5 ? 'WARN' : 'ALLOW',
        analysis_method: 'fallback'
      };
    }
  
    // ========== USER FEEDBACK ==========
  
    async sendUserFeedback(decision: SecurityDecision, userAction: 'accepted' | 'rejected' | 'overridden', feedback?: string): Promise<void> {
      try {
        const feedbackData = {
          wallet_provider_id: this.walletProviderId,
          original_decision: decision.action,
          risk_score: decision.risk_score,
          threat_categories: decision.threat_categories,
          user_action: userAction,
          user_feedback: feedback || '',
          timestamp: new Date().toISOString()
        };
        
        const response = await fetch(`${this.agentUrl}/api/v1/user-feedback`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Wallet-Provider': this.walletProviderId
          },
          body: JSON.stringify(feedbackData),
          signal: AbortSignal.timeout(5000)
        });
        
        if (response.ok) {
          console.log(`📚 Sent user feedback to AI: ${userAction}`);
        } else {
          console.warn(`⚠️ Failed to send feedback: ${response.status}`);
        }
      } catch (error) {
        console.warn(`⚠️ Could not send feedback to AI: ${error}`);
      }
    }
  
    // ========== UTILITY METHODS ==========
  
    setCallback(event: string, callback: SecurityCallback): void {
      if (event in this.callbacks) {
        this.callbacks[event] = callback;
        console.log(`📞 Set callback for ${event}`);
      }
    }
  
    // ========== BATCH ANALYSIS ==========
  
    async analyzeMultipleTokens(tokens: TransactionData[]): Promise<SecurityDecision[]> {
      console.log(`🔍 Analyzing ${tokens.length} tokens in batch`);
      
      const promises = tokens.map(token => this.analyzeToken(token));
      return await Promise.all(promises);
    }
  
    async analyzeTransactionBatch(transactions: TransactionData[]): Promise<SecurityDecision[]> {
      console.log(`🔍 Analyzing ${transactions.length} transactions in batch`);
      
      const promises = transactions.map(tx => 
        tx.transaction_type === 'incoming' ? 
          this.analyzeIncomingTransaction(tx) : 
          this.analyzeOutgoingTransaction(tx)
      );
      
      return await Promise.all(promises);
    }
  }