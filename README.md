# PolyMorph

Say hello toPolyMorph. PolyMorph is a polymorphic payload transformation engine for red team research. The tool helps you test how encoding/obfuscation chains affect the detectability of known payloads.
What's included:

polymorph_engine.c — C shared library with 15+ high-speed byte transforms: XOR (fixed & rolling), bit rotation, NOT, byte arithmetic, reversal, NOP insertion, hex/base64 encoding, and heuristic analysis (entropy, byte diversity, null counting, evasion scoring)
polymorph_engine.so — pre-compiled for Linux x86-64
polymorph.py — Python orchestrator using ctypes to call the C engine directly

Interactive widget above lets you visually build transform pipelines, inspect per-step entropy/evasion metrics, run the chain fuzzer (auto-generates and ranks hundreds of chains by evasion score), and export results.
