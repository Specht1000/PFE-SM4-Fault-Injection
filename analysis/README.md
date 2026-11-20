# Historical SM4 analysis

Only SM4-specific comparison results remain in results/sm4_comparison/.
They describe earlier simulated S-box-input fault models, not current physical
clock/voltage campaigns. Their figures and counts must not be presented as
measured hardware fault-injection results.

The older compare_sm4_attacks.py and analyze_sm4_recovery.py scripts still depend
on removed Giraud/logging support modules. They are retained as historical
SM4 analysis source, rather than current runnable entry points.

Current experiments:
~~~powershell
python src/piret_sm4.py
python chipwhisperer/sm4/clock_glitch.py --dry-run
python chipwhisperer/sm4/voltage_glitch.py --dry-run
~~~

The current report documents both physical methods and their output files.
Mixed-cipher scripts, datasets and charts were removed.
