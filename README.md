# PolyMorph

Say hello to PolyMorph. PolyMorph is a polymorphic payload transformation engine for red team research. The tool helps you test how encoding/obfuscation chains affect the detectability of known payloads.
What's included:

polymorph_engine.c — C shared library with 15+ high-speed byte transforms: XOR (fixed & rolling), bit rotation, NOT, byte arithmetic, reversal, NOP insertion, hex/base64 encoding, and heuristic analysis (entropy, byte diversity, null counting, evasion scoring)
polymorph_engine.so — pre-compiled for Linux x86-64
polymorph.py — Python orchestrator using ctypes to call the C engine directly

Interactive widget above lets you visually build transform pipelines, inspect per-step entropy/evasion metrics, run the chain fuzzer (auto-generates and ranks hundreds of chains by evasion score), and export results.


# Usage

# Compile on your system
gcc -shared -fPIC -O2 -o polymorph_engine.so polymorph_engine.c -lm

# Analyze a payload
python3 polymorph.py --payload 909090cccccccc --analyze

# Apply a transform chain + check bad chars
python3 polymorph.py --payload 909090cccccccc \
  --chain "xor_roll:0x41:0x13,bit_not,reverse" \
  --bad-chars "00,0a,0d" \
  --export c_array

# Auto-discover best evasion chains
python3 polymorph.py --payload <hex> --fuzz 100
