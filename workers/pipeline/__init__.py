"""Detection stages, runner, and verdict. Owned by workers; the API only reads
the SQLite rows these stages persist. AI never writes result.verdict.
"""
