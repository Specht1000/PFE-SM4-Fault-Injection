# Análises das cifras e dos ataques

Execute da raiz do projeto com Python 3.10 ou superior. Instale a dependência dos gráficos:

```powershell
python -m pip install -r analysis/requirements.txt
```

```powershell
python analysis/run_analysis.py
```

Para aumentar a amostra:

```powershell
python analysis/run_analysis.py --samples 4096 --avalanche-trials 16 --attack-trials 50 --seed 20261108
```

Os arquivos em `analysis/results/` são substituídos a cada execução:

- `report.md`: resultados, interpretação, modelos e limitações, em português.
- `measurements.json`: ambiente, hashes dos fontes, configuração, métricas, saídas corretas/falhas e evolução dos candidatos por ataque.
- `avalanche.csv`: distâncias de Hamming por bit de entrada, ensaio, cifra e tipo de alteração.
- `index.html`: galeria visual que abre localmente no navegador.
- `analysis_charts.pdf`: sete pranchas para exportação ou apresentação.
- `figures/`: gráficos em PNG e SVG vetorial, também incluídos no relatório.

Para recriar somente os gráficos com as medições já salvas:

```powershell
python analysis/plot_results.py
```

O experimento usa as funções reais de `src/`, sem alterar as cifras nem suas demonstrações. Os ensaios contêm chaves sintéticas públicas para permitir verificação. A seed reproduz as entradas; tempos variam conforme máquina e carga. As medidas das S-boxes são exaustivas; as medidas das cifras e ataques são amostrais. Não há avaliação física de hardware.
