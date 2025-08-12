# Bitcoin Address Risk Scorer

![Risk Report Screenshot](https://raw.githubusercontent.com/moemuf291/Bitles/refs/heads/main/Images/Screenshot%20(8).png)


This is a command-line tool to assess the risk level of a Bitcoin address based on its transaction history and interactions with a blacklist of suspicious addresses (e.g., related to darknet markets, money laundering, or other illicit activity).

The tool uses the Blockstream API to fetch on-chain data about the address and analyzes:

- Total transactions count  
- Total amount received  
- Largest transaction amount  
- Interactions with blacklisted addresses  
- Recency of activity  

It then produces a risk score (0-100) and classification (Low, Medium, High, Critical) with reasons.

---

## Features

- Fetches and analyzes up to 300 transactions per address by default  
- Supports user-provided blacklist JSON file containing blacklisted Bitcoin addresses  
- Scores risk based on transaction volume, flow imbalance, large transfers, and blacklist interactions  
- Classifies address status as active or dormant  
- Uses exponential backoff retry for API calls  

---

## Requirements

- Python 3.6+  
- `requests` library (`pip install requests`)  

---

## Usage

```bash
python3 btc_risk_scorer.py [address] [--blacklist BLACKLIST] [--max-txs MAX_TXS]
```

### Positional Arguments

| Argument | Description                |
|----------|----------------------------|
| `address` | Bitcoin address to analyze |

### Optional Arguments

| Option          | Description                                                                              | Default        |
|-----------------|------------------------------------------------------------------------------------------|----------------|
| `--blacklist`   | Path to JSON file with blacklist of suspicious Bitcoin addresses (JSON array of strings) | `blacklist.json` |
| `--max-txs`    | Maximum number of transactions to analyze (affects performance and depth of analysis)     | `300`          |

---

## Examples

Analyze a single address with the default blacklist:

```bash
python3 btc_risk_scorer.py 1BoatSLRHtKNngkdXEeobR76b53LETtpyT
```

Analyze with a custom blacklist file and max 500 transactions:

```bash
python3 btc_risk_scorer.py bc1qxyz... --blacklist my_blacklist.json --max-txs 500
```

---

## Screenshots

![Another Screenshot](https://raw.githubusercontent.com/moemuf291/Bitles/refs/heads/main/Images/Screenshot%20(9).png)


## Blacklist Format

The blacklist JSON file should be a simple JSON array of Bitcoin address strings, for example:

```json
[
  "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
  "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
]
```

---

## Exit Codes

| Code | Meaning                         |
|-------|---------------------------------|
| `0`   | Success                        |
| `1`   | Address not found or API error |
| `2`   | Failed to load blacklist       |

---

## How It Works (Summary)

- Loads the blacklist JSON  
- Fetches address stats from Blockstream API  
- Fetches recent transactions (up to max-txs)  
- Calculates largest sent/received amounts  
- Counts interactions with blacklisted addresses  
- Scores risk with heuristics based on activity, amounts, and blacklist interaction  
- Prints a formatted risk report  

---

If you find this tool useful or have questions, feel free to reach out!



## License

[MIT](https://choosealicense.com/licenses/mit/)



