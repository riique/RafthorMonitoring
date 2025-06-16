# RafthorMonitoring - Monitor de Rede Avançado

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![PyQt5](https://img.shields.io/badge/PyQt5-5.15-green.svg)
![Scapy](https://img.shields.io/badge/Scapy-2.6-orange.svg)

Um monitor de rede gráfico que captura e analisa tráfego DNS em tempo real, mostrando sites acessados, tempo gasto e dispositivos na rede.

## Funcionalidades Principais

- 🕵️ Monitoramento de tráfego DNS (IPv4 e IPv6)
- 📊 Interface gráfica moderna com PyQt5
- 🔍 Filtros avançados para portas 53, 80, 443 e 853
- 📈 Gráficos em tempo real de atividade da rede
- 📋 Relatórios detalhados com tempo gasto por site
- 🖥️ Identificação de dispositivos na rede

## Requisitos

- Python 3.10+
- Bibliotecas: `PyQt5`, `scapy`, `matplotlib`

## Instalação

1. Clone o repositório:
```bash
git clone https://github.com/seu-usuario/RafthorMonitoring.git
cd RafthorMonitoring/ee
```

2. Instale as dependências:
```bash
pip install -r requirements.txt
```

## Como Usar

Execute como administrador:
```powershell
Start-Process powershell -Verb RunAs -ArgumentList "cd C:\caminho\para\RafthorMonitoring\ee; python network_monitor_gui.py"
```

## Capturas de Tela

![Interface Principal](screenshots/main_window.png)
*Interface gráfica do monitor*

## Estrutura do Projeto

```
RafthorMonitoring/
├── ee/
│   ├── network_monitor_gui.py  # Aplicativo principal
│   ├── monitor.py              # Versão CLI (opcional)
│   └── README.md               # Este arquivo
└── screenshots/                # Capturas de tela (opcional)
```

## Contribuição

Contribuições são bem-vindas! Siga estes passos:

1. Faça um fork do projeto
2. Crie uma branch (`git checkout -b feature/nova-funcionalidade`)
3. Commit suas mudanças (`git commit -m 'Adiciona nova funcionalidade'`)
4. Push para a branch (`git push origin feature/nova-funcionalidade`)
5. Abra um Pull Request

## Licença

[MIT](https://choosealicense.com/licenses/mit/)
