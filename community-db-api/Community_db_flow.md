Wallet Provider A     Wallet Provider B     Wallet Provider C
      │                      │                      │
   SDK Agent              SDK Agent              SDK Agent
      │                      │                      │
      └──────────────────────┼──────────────────────┘
                             │
                   ┌─────────▼─────────┐
                   │  Community DB API  │
                   │  (Shared Backend)  │
                   └─────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
          RAG System    Background      External APIs
          (Shared)      Intelligence    (Jupiter, etc.)
                        (Shared)