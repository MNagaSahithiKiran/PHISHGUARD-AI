# PhishGuard AI — Intelligence Engine Architecture

## 1. High-Level System Architecture

```mermaid
flowchart TD
    Client[Web Frontend / SOC REST Client] -->|POST /api/v1/intelligence/analyze| API[FastAPI Intelligence Route]
    
    subgraph Security Layer
        API -->|Validate URL & Scheme| SSRF[SSRFGuard DNS/IP Firewall]
    end
    
    subgraph Tri-Modal Sensing Layer
        SSRF --> ModURL[Modality 1: URL Intelligence Model]
        SSRF --> ModWeb[Modality 2: Website HTTP/DOM Analyzer]
        SSRF --> ModVis[Modality 3: Isolated Playwright Browser & MobileNetV2]
    end
    
    subgraph Multi-Modal Intelligence Engine
        ModURL --> SignalAlign[Signal Aligner & Missing Modality Detector]
        ModWeb --> SignalAlign
        ModVis --> SignalAlign
        
        SignalAlign --> Router{Dynamic Modality Router}
        Router -->|Full 3 Modalities| FullStack[Full Stacking Meta-Classifier]
        Router -->|Visual Missing| UWStack[URL + Website Stacking Fallback]
        Router -->|Website Missing| UVStack[URL + Visual Stacking Fallback]
        Router -->|Offline / URL Only| UStack[URL Only Calibrated Fallback]
        
        FullStack --> RawProb[Raw Fusion Probability]
        UWStack --> RawProb
        UVStack --> RawProb
        UStack --> RawProb
        
        RawProb --> Calibrator[Platt Scaling Probability Calibrator]
        Calibrator --> CalProb[Calibrated Phishing Probability: 0.0 to 1.0]
    end
    
    subgraph Decision & Assessment
        CalProb --> Policy[Empirical Decision Policy: Legitimate / Suspicious / Phishing]
        CalProb --> RiskEngine[Risk Engine: 0-100 Score & Low / Medium / High]
    end
    
    subgraph Explainability & Evidence
        ModWeb --> EvidFuse[Evidence Fusion Synthesizer]
        ModVis --> EvidFuse
        CalProb --> Explainer[Multi-Modal Explainability Engine]
        EvidFuse --> Explainer
    end
    
    subgraph Persistence Layer
        Policy --> DB[(SQLite / PostgreSQL Records)]
        RiskEngine --> DB
        Explainer --> DB
    end
    
    DB --> Output[Standardized Intelligence JSON Response]
    Output --> Client
```

---

## 2. Dynamic Fallback Routing Logic

The Stacking Meta-Classifier (`ml/fusion/models/stacking_model.py`) contains specialized sub-models fitted on corresponding training features:

| Available Modality State | Activated Sub-Model | Features Ingested | Routing Mode Tag |
| :--- | :--- | :--- | :--- |
| **URL + Website + Visual** | `sub_models['full']` | $[P_{\text{url}}, P_{\text{website}}, P_{\text{visual}}]$ | `full_multimodal_stacking` |
| **URL + Website** | `sub_models['url_website']` | $[P_{\text{url}}, P_{\text{website}}]$ | `url_website_stacking_fallback` |
| **URL + Visual** | `sub_models['url_visual']` | $[P_{\text{url}}, P_{\text{visual}}]$ | `url_visual_stacking_fallback` |
| **URL Only** | `sub_models['url_only']` | $[P_{\text{url}}]$ | `url_only_stacking_fallback` |

---

## 3. Database Schema

```mermaid
erDiagram
    SCANS ||--o| FUSION_ANALYSES : "evaluates"
    FUSION_ANALYSES ||--o{ MODEL_EXECUTIONS : "records"
    FUSION_ANALYSES ||--o| EXPLANATIONS : "synthesizes"

    FUSION_ANALYSES {
        string id PK
        string scan_id FK
        text url
        string classification
        float raw_probability
        float calibrated_probability
        float risk_score
        string risk_level
        text modalities_used
        text missing_modalities
        string decision_policy_version
        string calibration_version
        float total_latency_ms
        datetime created_at
    }

    MODEL_EXECUTIONS {
        string id PK
        string fusion_analysis_id FK
        string modality
        string model_name
        string model_version
        string prediction
        float probability
        float latency_ms
        string status
    }

    EXPLANATIONS {
        string id PK
        string fusion_analysis_id FK
        text summary
        text key_signals
        text observed_evidence
        text feature_attributions
    }
```

---

## 4. REST API Endpoints

### 4.1 Execute Multi-Modal Assessment
`POST /api/v1/intelligence/analyze`

**Request**:
```json
{
  "url": "https://netflix-billing-reactivation.com",
  "include_visual": true
}
```

**Response**:
```json
{
  "scan_id": "8e3b2e59-cfa0-4bb5-a35f-149b8d227b68",
  "url": "https://netflix-billing-reactivation.com",
  "status": "completed",
  "classification": "phishing",
  "phishing_probability": 0.9634,
  "risk_score": 96.3,
  "risk_level": "high",
  "modalities_used": ["url", "website", "visual"],
  "missing_modalities": [],
  "models": {
    "url": { "model_name": "RandomForest_URLLexical", "probability": 0.9055 },
    "website": { "model_name": "DOM_Form_HeuristicAnalyzer", "probability": 0.9707 },
    "visual": { "model_name": "PhishMobileNetV2_Transfer", "probability": 0.9302 },
    "fusion": { "routing_mode": "full_multimodal_stacking", "calibrated_probability": 0.9634 }
  },
  "evidence": [
    {
      "category": "forms",
      "severity": "critical",
      "title": "Cross-Domain Password Action",
      "description": "Form targets external domain."
    }
  ],
  "explanation": {
    "summary": "Multi-modal fusion estimated an elevated phishing probability of 96.3% based on convergent signals across url, website, visual.",
    "classification": "phishing"
  },
  "performance": { "total_analysis_ms": 142.5 }
}
```

### 4.2 Query Assessment Record
`GET /api/v1/intelligence/{scan_id}`
Returns previously computed assessment and auditable data.
